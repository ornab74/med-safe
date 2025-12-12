from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a dependencies
    depends = ["python3"]
    python_depends = []

    # name inside site-packages
    site_packages_name = "llama_cpp_python"

    # we drive hostpython directly, not via targetpython
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        # p4a env for this recipe/arch (sets CC, CXX, CFLAGS, etc.)
        env = self.get_recipe_env(arch)

        # directory where p4a unpacked the tarball
        build_dir = self.get_build_dir(arch)

        # hostpython executable path from the toolchain context
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        with current_directory(build_dir):
            # --------------------------------------------------
            # 1) Make sure hostpython has pip
            # --------------------------------------------------
            try:
                shprint(hostpython_cmd, "-m", "pip", "--version", _env=env)
            except sh.ErrorReturnCode:
                # bootstrap pip into hostpython
                info("[llama_cpp_python] bootstrapping pip via ensurepip")
                shprint(
                    hostpython_cmd,
                    "-m",
                    "ensurepip",
                    "--upgrade",
                    _env=env,
                )

            # --------------------------------------------------
            # 2) Install / upgrade all build tools **inside hostpython**
            # --------------------------------------------------
            info("[llama_cpp_python] installing build tools (pip, wheel, cmake, ninja...)")
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
                _env=env,
            )

            # --------------------------------------------------
            # 3) Build llama-cpp-python from source for this arch
            # --------------------------------------------------
            info("[llama_cpp_python] building and installing from source")
            shprint(
                hostpython_cmd,
                "-m",
                "pip",
                "install",
                ".",                    # current source tree
                "--no-binary",
                ":all:",                # force from-source build
                "--no-build-isolation", # reuse the tools we just installed
                _env=env,
            )


# p4a entry point
recipe = LlamaCppPythonRecipe()
