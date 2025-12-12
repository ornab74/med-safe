from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    # Keep recipe name as your folder name under pythonforandroid/recipes/
    name = "llama_cpp_python"
    version = "0.3.2"

    # PyPI sdist includes vendored llama.cpp
    url = (
        "https://files.pythonhosted.org/packages/source/l/llama_cpp_python/"
        "llama_cpp_python-{version}.tar.gz"
    )

    depends = ["python3"]
    python_depends = []

    # IMPORTANT: installed top-level module is "llama_cpp", not "llama_cpp_python"
    # p4a uses this to decide whether install can be skipped. :contentReference[oaicite:3]{index=3}
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch):
        """Start from p4a's default env and add CMake flags for llama.cpp via CMAKE_ARGS."""
        env = super().get_recipe_env(arch)

        cmake_args = env.get("CMAKE_ARGS", "")

        # llama.cpp options can be set via CMAKE_ARGS. :contentReference[oaicite:4]{index=4}
        # Keep build minimal
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # Android NDK cross-compile guidance from llama.cpp: :contentReference[oaicite:5]{index=5}
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        # CPU-only (disable GPU backends explicitly)
        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        # Match llama.cpp android.md recommendation for modern devices. :contentReference[oaicite:6]{index=6}
        if getattr(arch, "arch", None) == "arm64-v8a":
            cmake_args += ' -DCMAKE_C_FLAGS="-march=armv8.7a"'
            cmake_args += ' -DCMAKE_CXX_FLAGS="-march=armv8.7a"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # If p4a injects -Werror flags, this keeps common “implicit” warnings from killing the build.
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (env.get(k, "") + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int").strip()

        # Some llama-cpp-python setups use FORCE_CMAKE to ensure cmake is used.
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
