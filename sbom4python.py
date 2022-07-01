# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

"""
This tool creates SBOMs (Software Bill of Materials) for Python
"""

import sys

from sbom4python.cli import main

sys.exit(main())