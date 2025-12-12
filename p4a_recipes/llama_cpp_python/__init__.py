from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory, shprint
from pythonforandroid.logger import info
import sh  # p4a uses 'sh' under the hood


class LlamaCppPythonRecipe(Recipe):
    """
    Minimal pyproject-style recipe for llama-cpp-python.

    We let pip + the p4a toolchain do the heavy lifting:
    - install cmake/ninja into the hostpython env
    - pip install .  (which builds C++ with the NDK toolchain)
    """

    name = "llama_cpp_python"
    # pick a known-good version; adjust if you like
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # pure python deps handled by pip inside build_arch
    depends = ["python3"]
    python_depends = []

    site_packages_name = "llama_cpp_python"
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        info(f"[llama_cpp_python] build_arch for {arch}")
        env = self.get_recipe_env(arch)
        hostpython = self.get_hostpython(arch)
        build_dir = self.get_build_dir(arch)

        with current_directory(build_dir):
            # make sure build tools exist in the hostpython env
            shprint(hostpython, "-m", "pip", "install", "cmake", "ninja", _env=env)

            # build from source for this arch, no prebuilt wheels
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
