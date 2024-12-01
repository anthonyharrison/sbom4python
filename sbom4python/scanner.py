# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import ast
import configparser
import pathlib
import platform
import re
import string
import subprocess
import sys
import unicodedata

import toml

if sys.version_info >= (3, 10):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata

import pkg_resources
from lib4package.metadata import Metadata
from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner
from sbom4files.filescanner import FileScanner


class SBOMScanner:
    """
    Simple SBOM Generator for Python module.
    """

    def __init__(
        self,
        debug,
        include_file=False,
        exclude_license=False,
        lifecycle="build",
        include_service=False,
        use_pip=False,
    ):
        self.record = []
        self.debug = debug
        self.include_file = include_file
        self.include_license = exclude_license
        self.include_service = include_service
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.sbom_document = SBOMDocument()
        self.file_scanner = FileScanner()
        self.license = LicenseScanner()
        self.sbom_files = {}
        self.sbom_packages = {}
        self.sbom_relationships = []
        self.parent = "NOT_DEFINED"
        self.package_metadata = Metadata("python", debug=self.debug)
        self.python_version = platform.python_version()
        self.set_lifecycle(lifecycle)
        self.metadata = {}
        self.use_pip = use_pip

    def set_parent(self, module):
        self.parent = f"Python-{module}"

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # Split command line into individual elements
        params = command_line.split()
        res = subprocess.run(params, capture_output=True, text=True)
        return res.stdout.splitlines()

    def set_lifecycle(self, lifecycle):
        self.sbom_document.set_value("lifecycle", lifecycle)

    def _format_supplier(self, supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        # And convert byte object to a string
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
            re.IGNORECASE,
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())

    def _create_package(self, package, version, parent="-", requirements=None):
        self.sbom_package.initialise()
        offline = False
        try:
            self.package_metadata.get_package(package, version)
        except Exception as ex:
            offline = True
            if self.debug:
                print(f"[ERROR] Unable to retrieve metadata for {package} - {ex}")
        self.sbom_package.set_name(package)
        self.sbom_package.set_property("language", "Python")
        self.sbom_package.set_property("python_version", self.python_version)
        if version is not None:
            self.sbom_package.set_version(version)
            if not offline:
                # External metadata may lag releases
                self.sbom_package.set_value(
                    "release_date", self.package_metadata.get_latest_release_time()
                )
        if requirements is not None:
            self.sbom_package.set_evidence(requirements)
        if parent == "-":
            self.sbom_package.set_type("application")
        self.sbom_package.set_filesanalysis(self.include_file)
        # Get package metadata
        if len(self.metadata) > 0:
            license_information = self.get("License")
            supplier = self.get("Author") + " " + self.get("Author-email")
            home_page = self.get("Home-page")
            summary = self.get("Summary")
        elif not offline:
            license_information = self.package_metadata.get_license()
            # Supplier info
            supplier = self.package_metadata.get_originator()
            if supplier is None:
                supplier = ""
            home_page = self.package_metadata.get_homepage()
            if home_page is None:
                home_page = ""
            summary = self.package_metadata.get_description()
            if summary is None:
                summary = ""
        else:
            license_information = ""
            supplier = ""
            home_page = ""
            summary = ""
        license = self.license.find_license(license_information)
        # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
        if license != license_information:
            self.sbom_package.set_licensedeclared("NOASSERTION")
        else:
            self.sbom_package.set_licensedeclared(license)
        # Report license if valid SPDX identifier
        self.sbom_package.set_licenseconcluded(license)
        # Add comment if metadata license was modified
        license_comment = ""
        if len(license_information) > 0 and license != license_information:
            license_comment = f"{package} declares {license_information} which is not currently a valid SPDX License identifier or expression."
        # Report if license is deprecated
        if self.license.deprecated(license):
            deprecated_comment = f"{license} is now deprecated."
            if len(license_comment) > 0:
                license_comment = f"{license_comment} {deprecated_comment}"
            else:
                license_comment = deprecated_comment
        if len(license_comment) > 0:
            self.sbom_package.set_licensecomments(license_comment)
        if len(supplier.split()) > 3:
            self.sbom_package.set_supplier(
                "Organization", self._format_supplier(supplier)
            )
        elif len(supplier) > 1:
            self.sbom_package.set_supplier("Person", self._format_supplier(supplier))
        else:
            self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
        if home_page != "":
            self.sbom_package.set_homepage(home_page)
        if summary != "":
            self.sbom_package.set_summary(summary)
        if self.metadata.get("Project-URL") is not None:
            # Extra references
            # Normalisation of labels
            chars_to_remove = string.punctuation + string.whitespace
            removal_map = str.maketrans("", "", chars_to_remove)
            # Various synonyms of project URLs
            categories = {
                "docs": "documentation",
                "source": "vcs",
                "repository": "vcs",
                "sourcecode": "vcs",
                "github": "vcs",
                "githubrepo": "vcs",
                "gitlab": "vcs",
                "bitbucket": "vcs",
                "git": "vcs",
                "sourceforge": "vcs",
                "svn": "vcs",
                "code": "vcs",
                "changelog": "log",
                "changes": "log",
                "docschangelog": "log",
                "whatsnew": "log",
                "issues": "issue-tracker",
                "bug": "issue-tracker",
                "bugs": "issue-tracker",
                "bugreports": "issue-tracker",
                "bugtracker": "issue-tracker",
                "issuetracker": "issue-tracker",
                "tracker": "issue-tracker",
                "githubissues": "issue-tracker",
                "mailinglist": "mailing-list",
                "mailinglists": "mailing-list",
                "sourcedistribution": "source-distribution",
                "ci": "build-system",
                "cigithub": "build-system",
                "cigithubactions": "build-system",
                "buildsystem": "build-systen",
                "releasenotes": "release-notes",
                "releasen": "release-notes",
                "twitter": "social",
                "discord": "social",
                "home": "home-page",
                "homepage": "home-page",
                "home page": "home-page",
            }
            for ref in self.metadata.get("Project-URL"):
                category = ref.split(", ")[0].translate(removal_map).lower()
                locator = ref.split(", ")[1]
                # See if synonymn
                if categories.get(category) is not None:
                    if self.debug:
                        print(
                            f"Updating category from {category} to {categories[category]}"
                        )
                    category = categories[category]
                if category == "home-page":
                    self.sbom_package.set_homepage(locator)
                else:
                    self.sbom_package.set_externalreference("OTHER", category, locator)
        if self.metadata.get("Download-URL") is None:
            if version is None:
                self.sbom_package.set_downloadlocation(
                    f"https://pypi.org/project/{package}/#files"
                )
            else:
                self.sbom_package.set_downloadlocation(
                    f"https://pypi.org/project/{package}/{version}/#files"
                )
        else:
            self.sbom_package.set_downloadlocation(self.metadata.get("Download-URL"))
        # External references
        if version is not None:
            self.sbom_package.set_purl(f"pkg:pypi/{package}@{version}")
        else:
            self.sbom_package.set_purl(f"pkg:pypi/{package}")
        if len(supplier) > 1:
            component_supplier = self._format_supplier(supplier, include_email=False)
            if version is not None:
                cpe_version = version.replace(":", "\\:")
            else:
                cpe_version = ""
            self.sbom_package.set_cpe(
                f"cpe:2.3:a:{component_supplier.replace(' ', '_').lower()}:{package}:{cpe_version}:*:*:*:*:*:*:*"
            )
        checksum, checksum_algorithm = self.package_metadata.get_checksum(
            version=version
        )
        if checksum is not None:
            self.sbom_package.set_checksum(checksum_algorithm, checksum)
        # Copyright
        self.sbom_package.set_copyrighttext("NOASSERTION")
        # Store package data
        self.sbom_packages[
            (
                self.sbom_package.get_name(),
                self.sbom_package.get_value("version"),
            )
        ] = self.sbom_package.get_package()

    def _create_relationship(self, package, parent="-"):
        self.sbom_relationship.initialise()
        if parent != "-":
            self.sbom_relationship.set_relationship(
                parent.lower(), "DEPENDS_ON", package
            )
        else:
            self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", package)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())

    def analyze_code(self, filename):
        """Analyzes Python code for potential external service interactions.

        Args:
            filename: The Python source file.

        Returns:
            A list of potential external service interactions.
        """
        potential_external_services = []
        modules = ["requests", "urllib", "httplib2"]
        potential_endpoint = []
        try:
            with open(filename, "r", errors="replace") as f:
                source_code = f.read()
            tree = ast.parse(source_code)

            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    # Check for function calls on http libraries like requests or urllib
                    if (
                        isinstance(node.value, ast.Name)
                        and (node.value.id in modules)
                        and node.attr in ["get", "post", "put", "delete"]
                    ):
                        if [
                            node.value.id,
                            node.attr,
                        ] not in potential_external_services:
                            potential_external_services.append(
                                [node.value.id, node.attr]
                            )
                elif isinstance(node, ast.Constant):
                    if node.value is not None:
                        constant = str(node.value)
                        if (
                            constant.startswith("http")
                            and "//" in constant
                            and len(constant) > 8
                        ):
                            # print (filename, constant)
                            potential_endpoint.append(constant)
        except FileNotFoundError:
            print(f"[ERROR] {filename} not found")
        except SyntaxError:
            # print(f"[ERROR] Unable to process {filename}.")
            pass
        if len(potential_external_services) > 0 and len(potential_endpoint) > 0:
            if self.debug:
                print(f"Potential endpoint in {filename}")
                for i in potential_endpoint:
                    print(i)
                for i in potential_external_services:
                    print(i)

            return potential_endpoint
        else:
            return []

    def _extract_package_name(self, requirement_string):
        for i, char in enumerate(requirement_string):
            # Ignore optional dependencies
            if "extra" in requirement_string:
                return ""
            # Paqckage names only contain alphanumeric characters and -_
            if not char.isalnum() and char not in ["-", "_"]:
                return requirement_string[:i]
        return requirement_string

    def _extract_package_names(self, requirements_list):
        return [self._extract_package_name(req) for req in requirements_list]

    def _getpackage_metadata(self, module):
        metadata = {}
        if self.use_pip:
            out = self.run_program(f"pip show {module}")
            for line in out:
                entry = line.split(":")
                # If: this line contain an non-empty entry delimited by ':'
                if (len(entry) == 2) and (entry[1] and not (entry[1].isspace())):
                    # Store all data after keyword
                    metadata[entry[0]] = (
                        line.split(f"{entry[0]}:", 1)[1].strip().rstrip("\n")
                    )
                elif len(entry) > 2:
                    # Likely to include URL
                    metadata[entry[0]] = (
                        line.split(f"{entry[0]}:", 1)[1].strip().rstrip("\n")
                    )
        else:
            try:
                package_data = importlib_metadata.metadata(module)
            except importlib_metadata.PackageNotFoundError:
                package_data = None
            if package_data is None:
                if self.debug:
                    print(f"Unable to retrieve metadata for {module}")
                return metadata
            package_metadata = dict(package_data)
            # Store subset of metadata (same as pip show <module>)
            for attribute in [
                "Name",
                "Version",
                "Summary",
                "Home-page",
                "Author",
                "Author-email",
                "License",
                "Download-URL",
            ]:
                if package_metadata.get(attribute) is not None:
                    metadata[attribute] = package_metadata[attribute]
            # License-Expresssion is preferred to License
            if package_metadata.get("License_Expression"):
                metadata["License"] = package_metadata["License_Expression"]
            # Project-URL (multiple)
            if package_metadata.get("Project-URL"):
                metadata["Project-URL"] = package_data.get_all("Project-URL")
            # Requires-Dist (multiple)
            if package_metadata.get("Requires-Dist"):
                requires = package_data.get_all("Requires-Dist")
            else:
                requires = None

            if requires is not None:
                # Find dependent packages
                if self.debug:
                    print(f"Dependencies for {module} - {requires}")

                package_names = self._extract_package_names(requires)

                package_dependendents = ""
                for name in package_names:
                    # Ignore extra packages
                    if len(name) > 0:
                        package_dependendents = (
                            package_dependendents + name.split(" ")[0] + ", "
                        )
                # Remove extra punctuation
                metadata["Requires"] = package_dependendents[:-2]
            else:
                metadata["Requires"] = ""
        if self.debug:
            print(metadata)
        return metadata

    def process_module(self, module, parent="-"):
        if self.debug:
            print(f"Process Module {module}")
        self.metadata = self._getpackage_metadata(module.strip())
        # If module not found, no metadata returned
        if len(self.metadata) > 0:
            package = self.get("Name").lower().replace("_", "-")
            version = self.get("Version")
            if (package, version) in self.sbom_packages:
                if self.debug:
                    print(f"Already processed {package} {version}")
                # Prevent metadata being reprocessed
                self.metadata = {}
            else:
                self._create_package(package, version, parent)
            self._create_relationship(package, parent)
            if self.include_file:
                package = self.get("Name").lower().replace("-", "_")
                directory_location = f'{self.get("Location")}/{package}'
                file_dir = pathlib.Path(directory_location)
                if self.debug:
                    print(f"Directory for {package}: {file_dir}")
                if file_dir.exists():
                    filtered = [x for x in file_dir.glob("**/*")]
                else:
                    # Module is only a single file
                    filtered = [pathlib.Path(f'{self.get("Location")}/{package}')]
                if self.debug:
                    print(f"Filenames: {filtered}")
                for entry in filtered:
                    # Ignore compiled code
                    if str(entry).endswith(".pyc"):
                        continue
                    if self.debug:
                        print(f"Analyse file in {entry}")
                    if self.include_service:
                        external_services = self.analyze_code(entry)
                        if len(external_services) > 0:
                            print(f"External services in {entry}")

                    if self.file_scanner.scan_file(entry):
                        self.sbom_files[
                            self.file_scanner.get_name()
                        ] = self.file_scanner.get_file()
                        # Add relationship
                        self.sbom_relationship.initialise()
                        self.sbom_relationship.set_relationship(
                            package, "CONTAINS", self.file_scanner.get_name()
                        )
                        self.sbom_relationship.set_relationship_id(
                            self.sbom_package.get_value("id"),
                            self.file_scanner.get_value("id"),
                        )
                        self.sbom_relationship.set_target_type("file")
                        self.sbom_relationships.append(
                            self.sbom_relationship.get_relationship()
                        )
        elif self.debug:
            print(f"Module {module} not found")
        return len(self.metadata) > 0

    def get(self, attribute):
        return self.metadata.get(attribute, "").lstrip()

    def get_files(self):
        return self.sbom_files

    def get_packages(self):
        return self.sbom_packages

    def get_relationships(self):
        if self.debug:
            print(self.sbom_relationships)
        return self.sbom_relationships

    def get_document(self):
        return self.sbom_document.get_document()

    def get_parent(self):
        return self.parent

    def analyze(self, parent, dependencies):
        if len(dependencies) == 0:
            return
        else:
            for r in dependencies.split(","):
                if self.process_module(r, parent):
                    self.analyze(r.strip(), self.get("Requires"))

    def process_python_module(self, module_name):
        self.set_parent(module_name)
        if self.process_module(module_name):
            self.analyze(self.get("Name"), self.get("Requires"))

    def _get_installed_modules(self):
        modules = []
        if self.use_pip:
            out = self.run_program("pip list")
            if len(out) > 0:
                # Ignore headers in output stream
                for m in out[2:]:
                    modules.append(m.split(" ")[0])
        else:
            installed_packages = pkg_resources.working_set
            modules = sorted(["%s" % (i.key) for i in installed_packages])
        if self.debug:
            print(modules)
        return modules

    def process_system(self):
        modules = self._get_installed_modules()
        self.set_parent("system")
        for module_name in modules:
            if self.process_module(module_name):
                self.analyze(self.get("Name"), self.get("Requires"))

    def process_requirements(self, filename):
        if filename.endswith(".toml"):
            self.process_pyproject(filename)
        elif filename.endswith(".cfg"):
            self.process_setup_cfg(filename)
        elif filename.endswith(".py"):
            self.process_setup_py(filename)
        elif filename.endswith(".txt"):
            self.process_requirements_file(filename)
        elif self.debug:
            print(f"Unable to process requirements file {filename}")

    def _process_requirement_dependency(self, dependency, filename):
        if len(dependency.strip()) > 0:
            # Ignore anything after ; e.g. python_version<"3.8"
            element = dependency.strip().split(";")[0]
            # Check for pinned dependency
            component = element.split("==")
            if len(component) == 2:
                # Package and version found
                package = component[0]
                version = component[1]
                if self.debug:
                    print(f"Processing {package} version {version}")
            else:
                # Not pinned version
                package = self._extract_package_name(element.split(" ")[0])
                version = None
                if self.debug:
                    print(f"Processing {package}")
            self._create_package(package, version, requirements=filename)
            self._create_relationship(package)

    def process_requirements_file(self, filename):
        # Process a requirements.txt file
        if len(filename) > 0:
            # Check file exists
            filePath = pathlib.Path(filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                with open(filename) as dir_file:
                    lines = dir_file.readlines()
                self.set_lifecycle("pre-build")
                self.set_parent(filename)
                for line in lines:
                    self._process_requirement_dependency(line, filename)

    def process_pyproject(self, filename):
        # Process pyproject.toml file
        if len(filename) > 0:
            # Check file exists
            filePath = pathlib.Path(filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                with open(filename) as file:
                    pyproject_data = toml.load(file)
                    if "project" in pyproject_data:
                        if "dependencies" in pyproject_data["project"]:
                            dependencies = pyproject_data["project"]["dependencies"]
                            if self.debug:
                                print(dependencies)
                            self.set_lifecycle("pre-build")
                            self.set_parent(filename)
                            for dependency in dependencies:
                                self._process_requirement_dependency(
                                    dependency, filename
                                )

    def process_setup_cfg(self, filename):
        # Process setup.cfg file
        if len(filename) > 0:
            # Check file exists
            filePath = pathlib.Path(filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                config = configparser.ConfigParser()
                config.read(filename)
                if "options" in config.sections():
                    if "install_requires" in config["options"]:
                        dependencies = config["options"]["install_requires"]
                        if self.debug:
                            print(dependencies)
                        self.set_lifecycle("pre-build")
                        self.set_parent(filename)
                        for dependency in dependencies.splitlines():
                            self._process_requirement_dependency(dependency, filename)

    def process_setup_py(self, filename):
        # Process setup.py file
        if len(filename) > 0:
            # Check file exists
            filePath = pathlib.Path(filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                dependencies = []
                with open(filename, "r") as setup_file:
                    # Read the file into a stream and search for list if dependencies specified by install_requires
                    stream = setup_file.read().replace("\n", "")
                    match = re.search(r"install_requires\s*=\s*\[([^\]]+)\]", stream)
                    if match:
                        dependency_list = match.group(1).strip()
                        dependencies = [
                            dep.strip().replace('"', "").replace("'", "")
                            for dep in dependency_list.split(",")
                            if len(dep) > 0
                        ]
                if self.debug:
                    print(dependencies)
                self.set_lifecycle("pre-build")
                self.set_parent(filename)
                for dependency in dependencies:
                    self._process_requirement_dependency(dependency, filename)
