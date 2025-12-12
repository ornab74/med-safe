from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    # This name must match what you use in
    # requirements = ... ,llama_cpp_python
    name = "llama_cpp_python"

    # Pick a version that works for you
    version = "0.3.2"
    url = (
        "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/"
        "v{version}.tar.gz"
    )

    # p4a-level deps
    depends = ["python3"]
    python_depends = []

    # name inside site-packages
    site_packages_name = "llama_cpp_python"

    # we call hostpython ourselves, not via targetpython
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        info(f"[llama_cpp_python] build_arch for {arch}")

        # Environment that p4a prepared for this arch (NDK, CFLAGS, etc.)
        env = self.get_recipe_env(arch)

        # Use the host Python that p4a already uses to build extensions
        hostpython = sh.Command(self.ctx.hostpython)

        # Directory where llama-cpp-python sources are unpacked
        build_dir = self.get_build_dir(arch)

        with current_directory(build_dir):
            info("[llama_cpp_python] installing build tools into hostpython env")

            # 1) Make sure pip + core build tooling is there
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
                # Build backends / helpers that show up in your logs
                "scikit-build-core",
                "flit_core",
                _env=env,
            )

            info("[llama_cpp_python] building and installing from source")

            # 2) Build llama-cpp-python itself.
            # --no-binary :all: forces a source build.
            # --no-build-isolation makes pip use the env we just populated
            # (so flit_core, scikit-build-core, etc. are available).
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                ".",
                "--no-binary",
                ":all:",
                "--no-build-isolation",
                _env=env,
            )


# p4a entry point
recipe = LlamaCppPythonRecipe()
