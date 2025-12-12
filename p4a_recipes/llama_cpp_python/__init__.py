
import os

from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    # Folder name under pythonforandroid/recipes/
    name = "llama_cpp_python"
    version = "0.3.2"

    # Exact 0.3.2 sdist URL (avoids 404)
    url = "https://files.pythonhosted.org/packages/5f/0e/ff129005a33b955088fc7e4ecb57e5500b604fb97eca55ce8688dbe59680/llama_cpp_python-0.3.2.tar.gz"

    depends = ["python3"]
    python_depends = []

    # Top-level import provided by the wheel is "llama_cpp"
    site_packages_name = "llama_cpp"

    # We drive hostpython directly, not via targetpython
    call_hostpython_via_targetpython = False

    def _strip_flag(self, s: str, flag: str) -> str:
        parts = s.split()
        parts = [p for p in parts if p != flag]
        return " ".join(parts)

    def _host_tools_env(self, base_env: dict) -> dict:
        """
        Env used only to install build tooling into hostpython.
        Avoid leaking Android cross-compile vars into the host tooling step.
        """
        env = dict(base_env)

        # Remove common cross-compile variables p4a sets
        for k in (
            "CC", "CXX", "AR", "AS", "LD", "STRIP", "RANLIB",
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
            "PKG_CONFIG", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
        ):
            env.pop(k, None)

        # Make sure user-site is enabled (pip may default to --user if system site-packages isn't writable)
        env["PYTHONNOUSERSITE"] = "0"

        # Keep pip quieter + deterministic
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        env.setdefault("PIP_NO_INPUT", "1")

        return env

    def get_recipe_env(self, arch):
        """
        Start from p4a's default env and add:
        - CMAKE_ARGS for llama.cpp/scikit-build-core
        - safer C/CXX flags (don’t let warnings or libc++ deprecations break the build)
        """
        env = super().get_recipe_env(arch)

        cmake_args = env.get("CMAKE_ARGS", "")

        # Build minimal llama.cpp bits
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # CPU-only / Android-friendly
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        # Force a stable language level (avoid any accidental newer-standard removals)
        cmake_args += " -DCMAKE_CXX_STANDARD=17"
        cmake_args += " -DCMAKE_CXX_STANDARD_REQUIRED=ON"
        cmake_args += " -DCMAKE_CXX_EXTENSIONS=OFF"

        # Verbose CMake logs (helps debugging)
        cmake_args += " -DCMAKE_VERBOSE_MAKEFILE=ON"

        # Your unicode.cpp / codecvt workaround:
        # - silence deprecated warnings
        # - re-enable removed codecvt/wstring_convert *if* something ends up in C++26 mode
        #   (these macros are documented by libc++).
        #   NOTE: macro names start with _LIBCPP... (leading underscore) :contentReference[oaicite:3]{index=3}
        cxx_codecvt_workaround = (
            "-Wno-deprecated-declarations "
            "-Wno-error=deprecated-declarations "
            "-D_LIBCPP_ENABLE_CXX26_REMOVED_CODECVT "
            "-D_LIBCPP_ENABLE_CXX26_REMOVED_WSTRING_CONVERT"
        )

        # Make sure we *append* extra flags instead of overwriting toolchain flags.
        # Also ensure -Werror=unused-command-line-argument can't kill us.
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = env.get(k, "")

        env["CXXFLAGS"] = self._strip_flag(env["CXXFLAGS"], "-Werror=unused-command-line-argument")
        env["CFLAGS"] = self._strip_flag(env["CFLAGS"], "-Werror=unused-command-line-argument")

        env["CFLAGS"] = (env["CFLAGS"] + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=unused-command-line-argument").strip()
        env["CXXFLAGS"] = (env["CXXFLAGS"] + " -Wno-error=unused-command-line-argument " + cxx_codecvt_workaround).strip()

        # Optional: modern ARM64 tuning (only for arm64-v8a)
        if getattr(arch, "arch", None) == "arm64-v8a":
            env["CFLAGS"] = (env["CFLAGS"] + " -march=armv8.7a").strip()
            env["CXXFLAGS"] = (env["CXXFLAGS"] + " -march=armv8.7a").strip()

        env["CMAKE_ARGS"] = cmake_args.strip()

        # scikit-build-core respects CMAKE_ARGS :contentReference[oaicite:4]{index=4}
        env.setdefault("SKBUILD_VERBOSE", "1")

        # llama-cpp-python often uses FORCE_CMAKE to force the CMake build path
        env.setdefault("FORCE_CMAKE", "1")

        # Keep user-site enabled
        env["PYTHONNOUSERSITE"] = "0"

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        target_env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)

        hostpython_cmd = sh.Command(self.ctx.hostpython)

        # Put pip-installed tooling in a writable per-arch userbase
        userbase = os.path.join(build_dir, "_hostpython_userbase")
        os.makedirs(userbase, exist_ok=True)

        target_env["PYTHONUSERBASE"] = userbase
        target_env["PYTHONNOUSERSITE"] = "0"

        host_env = self._host_tools_env(target_env)
        host_env["PYTHONUSERBASE"] = userbase

        with current_directory(build_dir):
            # 1) Ensure pip exists (hostpython often has no pip)
            # ensurepip bootstraps pip into the current Python install :contentReference[oaicite:5]{index=5}
            info("[llama_cpp_python] bootstrapping pip via ensurepip")
            shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", "--default-pip", _env=host_env)

            # 2) Install build backends/tools needed for pyproject builds
            # With --no-build-isolation, build requirements must already be installed :contentReference[oaicite:6]{index=6}
            info("[llama_cpp_python] installing build tooling/backends into hostpython userbase")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "cmake",
                "ninja",
                "typing_extensions",
                "numpy==1.26.4",
                "scikit-build-core",
                "flit-core",
                _env=host_env,
            )

            # Sanity-check backend import (this was your earlier crash)
            shprint(hostpython_cmd, "-c", "import flit_core.buildapi; print('flit_core OK')", _env=host_env)

            # 3) Build + install llama-cpp-python from source for this arch (very verbose)
            info("[llama_cpp_python] building+installing llama-cpp-python from source (very verbose)")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "-vvv",
                ".",
                "--no-deps",
                "--no-binary", ":all:",
                "--no-build-isolation",
                _env=target_env,
            )


recipe = LlamaCppPythonRecipe()
