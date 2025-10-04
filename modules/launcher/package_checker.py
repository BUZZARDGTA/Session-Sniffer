"""This module checks the validity of packages for the launcher."""
import importlib.metadata
from typing import TYPE_CHECKING, Literal

from packaging.requirements import Requirement

from modules.constants.local import PYPROJECT_DATA, REQUIREMENTS_PATH

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet


def get_dependencies_from_pyproject() -> dict[str, Requirement]:
    dependencies = PYPROJECT_DATA.get('project', {}).get('dependencies', [])

    return {
        req.name: req for req in map(Requirement, dependencies)
    }


def get_dependencies_from_requirements() -> dict[str, Requirement]:
    dependencies: dict[str, Requirement] = {}

    with REQUIREMENTS_PATH.open('r', encoding='utf-8') as f:
        for line in f:
            stripped_line = line.strip()
            if (
                not stripped_line
                or stripped_line.startswith('#')
            ):
                continue

            req = Requirement(stripped_line)
            dependencies[req.name] = req

    return dependencies


def check_packages_version(required_packages: dict[str, Requirement]) -> list[tuple[str, 'SpecifierSet', str]]:
    outdated_packages: list[tuple[str, SpecifierSet, str | Literal['Not Installed']]] = []  # noqa: PYI051
    for package_name, requirement in required_packages.items():
        try:
            installed_version = importlib.metadata.version(package_name)
            if installed_version not in Requirement(f'{package_name}{requirement}').specifier:
                outdated_packages.append((package_name, requirement.specifier, installed_version))
        except importlib.metadata.PackageNotFoundError:
            outdated_packages.append((package_name, requirement.specifier, 'Not Installed'))
    return outdated_packages
