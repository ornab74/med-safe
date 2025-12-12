from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    # you can bump this if you like, but keep a tag that exists
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a deps
    depends = ["python3"]
    python_depends = []

    # name inside site-packages
    site_packages_name = "llama_cpp_python"

    # we want to run hostpython directly, not via targetpython
    call_hostpython_via_targetpython = False

    # ---------------------------------------------------------
    # helpers
    # ---------------------------------------------------------
    def _ensure_pip(self, hostpython, env):
        """
        Make sure the hostpython used by p4a has pip available.
        Try ensurepip first, and if that fails, fall back to get-pip.py.
        """
        try:
            info("[llama_cpp_python] trying ensurepip for hostpython")
            shprint(hostpython, "-m", "ensurepip", "--upgrade", _env=env)
        except sh.ErrorReturnCode:
            info(
                "[llama_cpp_python] ensurepip not available, "
                "bootstrapping pip via get-pip.py"
            )
            # download get-pip.py into the build dir
            shprint(
                sh.wget,
                "https://bootstrap.pypa.io/get-pip.py",
                "-O",
                "get-pip.py",
                _env=env,
            )
            shprint(hostpython, "get-pip.py", _env=env)

    # ---------------------------------------------------------
    # main build
    # ---------------------------------------------------------
    def build_arch(self, arch):
        info(f"[llama_cpp_python] build_arch for arch {arch}")
        env = self.get_recipe_env(arch)
        # get_hostpython returns a string path – wrap it as a sh.Command
        hostpython = sh.Command(self.get_hostpython(arch))
        build_dir = self.get_build_dir(arch)

        with current_directory(build_dir):
            # 1) make sure pip exists in this hostpython
            self._ensure_pip(hostpython, env)

            # 2) install all build tools we need into that hostpython
            info("[llama_cpp_python] installing build tools with pip")
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "pip",
                "wheel",
                "setuptools",
                "cmake",
                "ninja",
                _env=env,
            )

            # 3) actually build llama-cpp-python from source for this arch
            info("[llama_cpp_python] building/Installing llama-cpp-python via pip")
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


# required by python-for-android
recipe = LlamaCppPythonRecipe()
