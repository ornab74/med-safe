from pythonforandroid.recipe import Recipe
from pythonforandroid.logger import shprint
from pythonforandroid.toolchain import current_directory, sh
import os


class LlamaCppPythonRecipe(Recipe):
    """
    Custom recipe to build llama-cpp-python for Android.

    - Uses pyproject / CMake via `pip install .`
    - Builds directly for the target arch using the NDK toolchain env
    """

    # Pick a version you’re happy with (0.3.x is current-ish)
    version = "0.3.2"

    # sdist from GitHub – avoids prebuilt wheels
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/v{version}.tar.gz"
    )

    # Name used in buildozer.spec requirements
    name = "llama_cpp_python"

    # p4a dependencies
    depends = ["python3"]
    python_depends = []

    # We don’t want the default host-then-target behaviour
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        super().build_arch(arch)

        env = self.get_recipe_env(arch)

        # Required for scikit-build-core / CMake builds
        env.setdefault("CMAKE_ARGS", "")
        env["CMAKE_ARGS"] += " -DLLAMA_CUBLAS=OFF -DLLAMA_CLBLAST=OFF"

        # Extra flags for Android if needed
        env.setdefault("CFLAGS", "")
        env.setdefault("CXXFLAGS", "")
        env.setdefault("LDFLAGS", "")

        build_dir = self.get_build_dir(arch)
        install_dir = self.ctx.get_python_install_dir(arch)

        hostpython = self.get_hostpython(arch)

        with current_directory(build_dir):
            # Ensure pip + build tools are available in target env
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "cmake",
                "ninja",
                _env=env,
            )

            # Build and install llama-cpp-python for the target
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                ".",
                "--no-binary",
                ":all:",
                "--prefix",
                install_dir,
                _env=env,
            )


recipe = LlamaCppPythonRecipe()
