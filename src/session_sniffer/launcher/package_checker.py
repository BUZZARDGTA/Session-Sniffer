"""The module checks the validity of packages for the launcher."""

import importlib.metadata
from typing import TYPE_CHECKING

from packaging.requirements import Requirement

from session_sniffer.constants.local import PYPROJECT_DATA

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet


def get_dependencies_from_pyproject() -> dict[str, Requirement]:
    """Return dependency requirements parsed from `pyproject.toml` for the current environment."""
    dependencies = PYPROJECT_DATA.get('project', {}).get('dependencies', [])

    return {
        requirement.name: requirement
        for requirement in map(Requirement, dependencies)
        if requirement.marker is None or requirement.marker.evaluate()
    }


def check_packages_version(required_packages: dict[str, Requirement]) -> list[tuple[str, SpecifierSet, str]]:
    """Compare installed versions against requirements and return mismatches."""
    outdated_packages: list[tuple[str, SpecifierSet, str]] = []
    for package_name, requirement in required_packages.items():
        try:
            installed_version = importlib.metadata.version(package_name)
            if installed_version not in requirement.specifier:
                outdated_packages.append((package_name, requirement.specifier, installed_version))
        except importlib.metadata.PackageNotFoundError:
            outdated_packages.append((package_name, requirement.specifier, 'Not Installed'))
    return outdated_packages
