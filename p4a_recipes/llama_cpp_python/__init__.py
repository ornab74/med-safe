from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh  # p4a uses 'sh' for running commands


class LlamaCppPythonRecipe(Recipe):
    # Name must match what you put in buildozer.spec requirements
    # requirements = ... ,llama_cpp_python
    name = "llama_cpp_python"
    version = "0.3.2"

    # Standard llama-cpp-python GitHub tarball
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a dependencies
    depends = ["python3"]
    python_depends = []

    # This must be the *import* name from your app:  `from llama_cpp import Llama`
    site_packages_name = "llama_cpp"

    # We’re going to drive hostpython ourselves
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        info(f"[llama_cpp_python] build_arch for {arch.arch}")

        env = self.get_recipe_env(arch)

        # p4a exposes the hostpython executable on the context
        hostpython = sh.Command(self.ctx.hostpython)

        build_dir = self.get_build_dir(arch)

        with current_directory(build_dir):
            # 1) make sure hostpython has pip
            shprint(hostpython, "-m", "ensurepip", "--upgrade", _env=env)

            # 2) upgrade pip/setuptools/wheel (needed for pyproject builds)
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                _env=env,
            )

            # 3) tools that llama-cpp-python’s build needs
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                "cmake",
                "ninja",
                _env=env,
            )

            # 4) finally build llama-cpp-python from source for this arch
            shprint(
                hostpython,
                "-m", "pip",
                "install",
                ".",
                "--no-binary",
                ":all:",
                _env=env,
            )


# p4a entry-point
recipe = LlamaCppPythonRecipe()
