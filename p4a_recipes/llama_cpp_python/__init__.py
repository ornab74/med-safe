import os

from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint


class LlamaCppPythonRecipe(Recipe):
    # Name used in buildozer.spec requirements line
    name = "llama_cpp_python"

    # Version of abetlen/llama-cpp-python to build
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # Normal p4a metadata
    depends = ["python3"]
    python_depends = []
    site_packages_name = "llama_cpp_python"
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        """
        Custom build step:

        1. Enter the unpacked llama-cpp-python source dir.
        2. Install build tools into hostpython (cmake, ninja, etc.).
        3. Drop a minimal setup.py so python-for-android's default
           Recipe.build_arch() can run `setup.py install`.
        4. Hand back to the parent implementation.
        """
        ctx = self.ctx
        hostpython = ctx.hostpython  # <- this replaces get_hostpython(...)
        build_dir = self.get_build_dir(arch)
        env = self.get_recipe_env(arch)

        info(f"[llama_cpp_python] building for arch {arch.arch} in {build_dir}")

        with current_directory(build_dir):
            # Ensure pip and basic build frontend pieces
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                "--upgrade",
                "pip",
                "wheel",
                "setuptools",
                _env=env,
            )

            # Core C/C++ build tools required by llama-cpp-python
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                "cmake",
                "ninja",
                "scikit-build-core",
                _env=env,
            )

            # Make sure a minimal setup.py exists so p4a can call it
            if not os.path.exists("setup.py"):
                info("[llama_cpp_python] creating stub setup.py")
                with open("setup.py", "w", encoding="utf-8") as f:
                    f.write("from setuptools import setup\n")
                    f.write("setup()\n")

        # Let the default Recipe logic do the actual cross install
        # (this will run `hostpython setup.py install ...` in build_dir)
        super().build_arch(arch)


# p4a entry point
recipe = LlamaCppPythonRecipe()
