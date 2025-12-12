from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    # Keep recipe name as your folder name under pythonforandroid/recipes/
    name = "llama_cpp_python"
    version = "0.3.2"

    # PyPI sdist (0.3.2) - exact URL from https://pypi.org/simple/llama-cpp-python/
    # This avoids the 404 you were hitting with the wrong /packages/source/... folder path.
    url = "https://files.pythonhosted.org/packages/5f/0e/ff129005a33b955088fc7e4ecb57e5500b604fb97eca55ce8688dbe59680/llama_cpp_python-0.3.2.tar.gz"

    depends = ["python3"]
    python_depends = []

    # Installed top-level module folder is "llama_cpp"
    # (p4a uses this to detect whether installation can be skipped). :contentReference[oaicite:2]{index=2}
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch):
        """Start from p4a's default env and add CMake flags for llama.cpp via CMAKE_ARGS."""
        env = super().get_recipe_env(arch)

        cmake_args = env.get("CMAKE_ARGS", "")

        # llama.cpp options can be set via CMAKE_ARGS in llama-cpp-python installs. :contentReference[oaicite:3]{index=3}
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # Android-friendly / CPU-only
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        if getattr(arch, "arch", None) == "arm64-v8a":
            cmake_args += ' -DCMAKE_C_FLAGS="-march=armv8.7a"'
            cmake_args += ' -DCMAKE_CXX_FLAGS="-march=armv8.7a"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # If p4a injects -Werror flags, this helps avoid common "implicit" warnings killing the build.
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (env.get(k, "") + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int").strip()

        # Forces the cmake-based build path when applicable
        env.setdefault("FORCE_CMAKE", "1")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        with current_directory(build_dir):
            # 1) Ensure pip exists
            try:
                shprint(hostpython_cmd, "-m", "pip", "--version", _env=env)
            except sh.ErrorReturnCode:
                info("[llama_cpp_python] bootstrapping pip via ensurepip")
                shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", _env=env)

            # 2) Build tooling inside hostpython
            info("[llama_cpp_python] installing build tools (pip/wheel/cmake/ninja/...)")
            shprint(
                hostpython_cmd,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "scikit-build-core",
                "cmake",
                "ninja",
                "typing_extensions",
                "numpy==1.26.4",
                _env=env,
            )

            # 3) Build + install from source with verbose output
            info("[llama_cpp_python] building and installing from source (verbose)")
            shprint(
                hostpython_cmd,
                "-m",
                "pip",
                "install",
                "-v",
                ".",
                "--no-binary",
                ":all:",
                "--no-build-isolation",
                _env=env,
            )


recipe = LlamaCppPythonRecipe()
