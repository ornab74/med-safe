import os

from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"

    # Exact 0.3.2 sdist URL (avoids 404)
    url = "https://files.pythonhosted.org/packages/5f/0e/ff129005a33b955088fc7e4ecb57e5500b604fb97eca55ce8688dbe59680/llama_cpp_python-0.3.2.tar.gz"

    depends = ["python3"]
    python_depends = []

    # Top-level import is llama_cpp (not llama_cpp_python)
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def _host_tools_env(self, base_env: dict) -> dict:
        """
        pip-install build tooling in a *host* env.
        Do NOT leak Android cross-compile CC/CFLAGS into this step.
        """
        env = dict(base_env)

        # Remove common cross-compile variables p4a sets
        for k in (
            "CC", "CXX", "AR", "AS", "LD", "STRIP", "RANLIB",
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
            "PKG_CONFIG", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
        ):
            env.pop(k, None)

        # Ensure user site is enabled
        env["PYTHONNOUSERSITE"] = "0"
        return env

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)

        # --- Make scikit-build-core show useful errors ---
        # Force Makefiles so the failing compiler command + error text is printed
        env["CMAKE_GENERATOR"] = "Unix Makefiles"

        # Make CMake/pip output much louder and reduce parallelism (helps avoid "no output" + OOM-ish failures)
        env.setdefault("SKBUILD_CMAKE_VERBOSE", "1")
        env.setdefault("CMAKE_BUILD_PARALLEL_LEVEL", "1")

        cmake_args = env.get("CMAKE_ARGS", "")

        # llama-cpp-python forwards llama.cpp options via CMAKE_ARGS
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # Android/CPU-friendly
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        # Disable GPU backends
        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        # Make build logs louder
        cmake_args += " -DCMAKE_VERBOSE_MAKEFILE=ON"

        # ---- Your requested unicode.cpp / codecvt protection ----
        # unicode.cpp uses deprecated codecvt on Android NDK; don’t let warnings kill the build
        # (also keeps builds working if libc++ hides removed codecvt symbols in newer modes)
        cxx_silence = (
            "-Wno-deprecated-declarations "
            "-Wno-error=deprecated-declarations "
            "-Wno-unused-command-line-argument "
            "-Wno-error=unused-command-line-argument "
            "-D_LIBCPP_ENABLE_CXX17_REMOVED_CODECVT"
        )

        extra_c_flags = [
            "-Wno-unused-command-line-argument",
            "-Wno-error=unused-command-line-argument",
        ]
        extra_cxx_flags = [cxx_silence]

        # Optional: modern ARM64 tuning (only for arm64)
        if getattr(arch, "arch", None) == "arm64-v8a":
            extra_c_flags.append("-march=armv8.7a")
            extra_cxx_flags.append("-march=armv8.7a")

        # IMPORTANT: set these once (avoid overwriting via multiple -DCMAKE_CXX_FLAGS=...)
        if extra_c_flags:
            cmake_args += f' -DCMAKE_C_FLAGS="{" ".join(extra_c_flags)}"'
        if extra_cxx_flags:
            cmake_args += f' -DCMAKE_CXX_FLAGS="{" ".join(extra_cxx_flags)}"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # Keep user-site enabled (GitHub runners often install with --user)
        env["PYTHONNOUSERSITE"] = "0"

        # Avoid strict -Werror pitfalls p4a sometimes injects
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (
                env.get(k, "")
                + " -Wno-error=implicit-function-declaration"
                + " -Wno-error=implicit-int"
                + " -Wno-unused-command-line-argument"
                + " -Wno-error=unused-command-line-argument"
            ).strip()

        # Helps some llama-cpp-python builds
        env.setdefault("FORCE_CMAKE", "1")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        target_env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        # Put all pip-installed tooling in a writable per-arch userbase
        userbase = os.path.join(build_dir, "_hostpython_userbase")
        os.makedirs(userbase, exist_ok=True)

        target_env["PYTHONUSERBASE"] = userbase
        host_env = self._host_tools_env(target_env)
        host_env["PYTHONUSERBASE"] = userbase

        with current_directory(build_dir):
            # 1) Ensure pip exists
            info("[llama_cpp_python] bootstrapping pip via ensurepip")
            shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", "--default-pip", _env=host_env)

            # 2) Install build backends/tools needed for pyproject build
            info("[llama_cpp_python] installing build backends/tools (host env)")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "cmake",
                # NOTE: do NOT install ninja; we force Unix Makefiles via CMAKE_GENERATOR
                "typing_extensions",
                "numpy==1.26.4",
                "scikit-build-core",
                "flit-core",
                _env=host_env,
            )

            # Sanity check for the flit backend import
            shprint(hostpython_cmd, "-c", "import flit_core.buildapi; print('flit_core OK')", _env=host_env)

            # 3) Build + install package for target (verbose, no deps)
            info("[llama_cpp_python] building+installing (target env, very verbose)")
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
