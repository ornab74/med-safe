import os
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"

    # Stable PyPI source URL (project path uses hyphens; filename uses underscores)
    url = (
        "https://files.pythonhosted.org/packages/source/l/llama-cpp-python/"
        "llama_cpp_python-{version}.tar.gz"
    )

    depends = ["python3"]
    python_depends = []

    # Top-level import is llama_cpp
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def _host_tools_env(self, base_env: dict) -> dict:
        """
        Install build tooling (pip/flit/cmake/ninja/...) in a *host* environment.
        Avoid leaking Android cross-compile vars into this step.
        """
        env = dict(base_env)

        for k in (
            "CC", "CXX", "AR", "AS", "LD", "STRIP", "RANLIB",
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
            "PKG_CONFIG", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
        ):
            env.pop(k, None)

        env["PYTHONNOUSERSITE"] = "0"
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        env.setdefault("PIP_NO_INPUT", "1")
        return env

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)

        # unicode.cpp uses deprecated codecvt on Android NDK/libc++;
        # don’t let warnings kill the build, and re-enable removed codecvt symbols if needed.
        cxx_silence = (
            "-Wno-deprecated-declarations "
            "-Wno-error=deprecated-declarations "
            "-D_LIBCPP_ENABLE_CXX17_REMOVED_CODECVT"
        )

        cmake_args = env.get("CMAKE_ARGS", "")

        # Minimal llama.cpp build
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # Android/CPU-friendly
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        # CPU-only
        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        cmake_args += " -DCMAKE_VERBOSE_MAKEFILE=ON"

        # IMPORTANT: don't overwrite CMAKE_CXX_FLAGS twice; merge -march + cxx_silence
        if getattr(arch, "arch", None) == "arm64-v8a":
            cmake_args += ' -DCMAKE_C_FLAGS="-march=armv8.7a"'
            cmake_args += f' -DCMAKE_CXX_FLAGS="-march=armv8.7a {cxx_silence}"'
        else:
            cmake_args += f' -DCMAKE_CXX_FLAGS="{cxx_silence}"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # Keep user-site enabled
        env["PYTHONNOUSERSITE"] = "0"

        # Reduce strict warning->error pain from p4a toolchains
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (
                env.get(k, "")
                + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int"
                + " -Wno-deprecated-declarations -Wno-error=deprecated-declarations"
            ).strip()

        env.setdefault("FORCE_CMAKE", "1")
        env.setdefault("SKBUILD_VERBOSE", "1")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        target_env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        host_env = self._host_tools_env(target_env)

        with current_directory(build_dir):
            # Use a venv so build backends (flit-core/scikit-build-core) are importable & writable.
            # With --no-build-isolation, build requirements must already be installed. :contentReference[oaicite:1]{index=1}
            venv_dir = os.path.join(build_dir, "_hostpython_venv")
            venv_python = os.path.join(venv_dir, "bin", "python")

            if not os.path.exists(venv_python):
                info("[llama_cpp_python] creating venv for build tooling")
                shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", "--default-pip", _env=host_env)
                shprint(hostpython_cmd, "-m", "venv", venv_dir, _env=host_env)

            vpy = sh.Command(venv_python)

            # Install build backends/tools (flit-core provides flit_core.buildapi) :contentReference[oaicite:2]{index=2}
            info("[llama_cpp_python] installing build backends/tools in venv")
            shprint(
                vpy, "-m", "pip", "install", "--upgrade",
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

            # Sanity check
            shprint(vpy, "-c", "import flit_core.buildapi; print('flit_core OK')", _env=host_env)

            # Build + install (very verbose)
            info("[llama_cpp_python] building+installing (target env, very verbose)")
            shprint(
                vpy,
                "-m", "pip", "install",
                "-vvv",
                ".",
                "--no-deps",
                "--no-binary", ":all:",
                "--no-build-isolation",
                _env=target_env,
            )


recipe = LlamaCppPythonRecipe()
