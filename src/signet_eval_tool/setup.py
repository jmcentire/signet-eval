#!/usr/bin/env python3
from setuptools import setup

setup(
    name='signet-eval-tool',
    version='1.0.0',
    description='Signet Evaluation Tool - Standalone CLI tool for evaluating Claude Code PreToolUse hooks',
    py_modules=['signet_eval_tool'],
    python_requires='>=3.12',
    install_requires=['pyyaml>=6.0'],
    entry_points={
        'console_scripts': [
            'signet-eval=signet_eval_tool:main',
        ],
    },
)
