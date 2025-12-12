from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"

    # We deliberately don't use a tarball URL any more.
    # pip will fetch llama-cpp-python from PyPI instead.
    url = None

    # p4a dependencies
    depends = ["python3"]
    python_depends = []

    # name inside site-packages
    site_packages_name = "llama_cpp_python"

    # we drive hostpython directly, not via targetpython
    call_hostpython_via_targetpython = False

    # --------------------------------------------------
    # Disable the default "download the URL" behaviour
    # that is currently giving HTTP 404 errors.
    # --------------------------------------------------
    def download_if_necessary(self, arch):
        info("[llama_cpp_python] skipping recipe URL download; using pip from PyPI instead.")

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        # p4a env for this recipe/arch (sets CC, CXX, CFLAGS, etc.)
        env = self.get_recipe_env(arch)

        # hostpython executable path from the toolchain context
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        # We don't need to cd into a build_dir now, because pip
        # will fetch the source from PyPI rather than from a local tarball.
        with current_directory("."):
            # --------------------------------------------------
            # 1) Make sure hostpython has pip
            # --------------------------------------------------
            try:
                shprint(hostpython_cmd, "-m", "pip", "--version", _env=env)
            except sh.ErrorReturnCode:
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
            info("[llama_cpp_python] installing build tools (pip, wheel, cmake, ninja, numpy...)")
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
                "flit_core",
                "meson-python",
                "typing_extensions",
                "numpy==1.26.4",
                "ninja",
                _env=env,
            )

            # --------------------------------------------------
            # 3) Build llama-cpp-python from source for this arch
            #    directly from PyPI
            # --------------------------------------------------
            info("[llama_cpp_python] installing llama-cpp-python from PyPI (source build)")
            shprint(
                hostpython_cmd,
                "-m",
                "pip",
                "install",
                f"llama-cpp-python=={self.version}",
                "--no-binary",
                ":all:",                # force from-source build
                "--no-build-isolation", # reuse the tools we just installed
                _env=env,
            )


# p4a entry point
recipe = LlamaCppPythonRecipe()
