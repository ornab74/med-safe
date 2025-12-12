# p4a_recipes/llama_cpp_python/__init__.py

from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(PythonRecipe):
    # visible name used in buildozer.spec "requirements"
    name = "llama_cpp_python"

    # pick a version you know works for you
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a deps
    depends = ["python3"]
    python_depends = []

    # how it will be installed into site-packages
    site_packages_name = "llama_cpp_python"

    # we explicitly drive hostpython, so don’t proxy via targetpython
    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch):
        # start from the standard PythonRecipe env (gives us CC, CXX, NDK paths)
        env = super().get_recipe_env(arch)

        # IMPORTANT: let the pyproject build see our tools instead of
        # creating its own isolated venv where cmake/ninja aren't installed
        env["PIP_NO_BUILD_ISOLATION"] = "1"

        # hint for scikit-build-core
        env.setdefault("SKBUILD_CMAKE_GENERATOR", "Ninja")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        env = self.get_recipe_env(arch)
        # PythonRecipe gives us a usable interpreter path for hostpython
        hostpython_path = self.get_hostpython(arch)
        hostpython = sh.Command(hostpython_path)

        build_dir = self.get_build_dir(arch)

        with current_directory(build_dir):
            # --- make sure hostpython has pip itself -------------------------
            try:
                shprint(hostpython, "-m", "pip", "--version", _env=env)
            except sh.ErrorReturnCode:
                # bootstrap pip into this interpreter if it’s missing
                shprint(hostpython, "-m", "ensurepip", "--upgrade", _env=env)

            # --- core build tools (keep them ALL, as you asked) --------------
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                _env=env,
            )

            # tools used by llama-cpp-python’s pyproject/scikit-build
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "cmake",
                "ninja",
                "scikit-build-core",
                _env=env,
            )

            # --- finally build llama-cpp-python itself -----------------------
            # --no-binary :all: forces a full C/C++ build using our NDK + CMake.
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


# p4a entry-point
recipe = LlamaCppPythonRecipe()
