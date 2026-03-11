"""Sphinx configuration for scp-python Python API reference."""

import os
import sys

sys.path.insert(0, os.path.abspath(".."))

project = "scp-python"
author = "Limn"
release = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

autodoc_typehints = "description"
autodoc_member_order = "bysource"
napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_theme = "furo"
html_title = "scp-python"

exclude_patterns = ["_build"]
