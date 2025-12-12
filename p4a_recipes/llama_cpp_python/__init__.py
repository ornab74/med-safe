from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh  # p4a uses 'sh' under the hood


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a deps
    depends = ["python3"]
    python_depends = []
    site_packages_name = "llama_cpp_python"
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        info(f"[llama_cpp_python] build_arch for {arch}")
        env = self.get_recipe_env(arch)
        hostpython = self.get_hostpython(arch)
        build_dir = self.get_build_dir(arch)

        # Make sure we don’t accidentally try to build CUDA/cuBLAS stuff on Android
        env.setdefault("CMAKE_ARGS", "")
        env["CMAKE_ARGS"] += (
            " -DLLAMA_CUBLAS=OFF"
            " -DLLAMA_CUDA=OFF"
            " -DLLAMA_OPENBLAS=OFF"
        )
        env["LLAMA_CUBLAS"] = "0"
        env["LLAMA_CUDA"] = "0"
        env["LLAMA_OPENBLAS"] = "0"

        with current_directory(build_dir):
            # --- Build toolchain for pyproject / CMake build ---
            # Install everything needed to compile llama-cpp-python from source
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                "cmake",
                "ninja",
                "scikit-build-core",
                "setuptools",
                "wheel",
                "packaging",
                _env=env,
            )

            # --- Actual build/install for this arch ---
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                ".",
                "--no-binary",
                ":all:",
                _env=env,
            )


recipe = LlamaCppPythonRecipe()
