from typing import Any
from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from pathlib import Path
import shutil


class AppsBuildHook(BuildHookInterface):
    def finalize(
        self, version: str, build_data: dict[str, Any], artifact_path: str
    ) -> None:
        self.app.display_info(
            f"Running Databricks Apps build hook for project {self.metadata.name} in directory {Path.cwd()}"
        )
        # remove the ./.build folder if it exists
        build_dir = Path(".build")
        self.app.display_info(f"Resulting build directory: {build_dir.absolute()}")

        if build_dir.exists():
            self.app.display_info(f"Removing {build_dir}")
            shutil.rmtree(build_dir)
            self.app.display_info(f"Removed {build_dir}")
        else:
            self.app.display_info(f"{build_dir} does not exist, skipping removal")

        # copy the artifact_path to the ./.build folder
        build_dir.mkdir(exist_ok=True)
        self.app.display_info(f"Copying {artifact_path} to {build_dir}")
        shutil.copy(artifact_path, build_dir)

        # write the name of the artifact to a requirements.txt file in the ./.build folder
        requirements_file = build_dir / "requirements.txt"

        requirements_file.write_text(Path(artifact_path).name, encoding="utf-8")

        self.app.display_info(
            f"Apps-compatible build written to {build_dir.absolute()}"
        )
