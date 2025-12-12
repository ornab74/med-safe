import os
import sh  # <-- make sure this import is present

from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    depends = ["python3"]
    python_depends = []
    site_packages_name = "llama_cpp_python"
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        ctx = self.ctx
        # IMPORTANT: wrap hostpython path in sh.Command
        hostpython = sh.Command(ctx.hostpython)
        build_dir = self.get_build_dir(arch)
        env = self.get_recipe_env(arch)

        info(f"[llama_cpp_python] building for arch {arch.arch} in {build_dir}")

        with current_directory(build_dir):
            # ensure build front-end tools
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

            # C/C++ build tools used by llama-cpp-python
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                "cmake",
                "ninja",
                "scikit-build-core",
                _env=env,
            )

            # stub setup.py so p4a’s default build can run
            if not os.path.exists("setup.py"):
                info("[llama_cpp_python] creating stub setup.py")
                with open("setup.py", "w", encoding="utf-8") as f:
                    f.write("from setuptools import setup\n")
                    f.write("setup()\n")

        # hand back to standard p4a Recipe logic
        super().build_arch(arch)


recipe = LlamaCppPythonRecipe()
