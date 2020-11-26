# Copyright (C) <2020> Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

'''Script for build in continuous integration environment.
'''

import os
import subprocess
import sys
from pathlib import Path
import shutil

SRC_PATH = Path(__file__).resolve().parents[3]
PATCH_PATH = SRC_PATH/'owt'/'quic_transport'/'patches'
SDK_TARGET_NAME = 'owt_quic_transport'
PATCH_LIST = [
    ('0001-Add-owt_quic_transport-to-BUILD.gn.patch', SRC_PATH)
]


def sync():
    subprocess.call(['gclient', 'sync'], cwd=SRC_PATH, shell=False)


def patch():
    for file_name, path in PATCH_LIST:
        if(subprocess.call(['git', 'am', str(PATCH_PATH/file_name)], cwd=path)) != 0:
            subprocess.call(['git', 'am', '--skip'], cwd=path)


def create_gclient_args():
    gclient_args_path = Path(SRC_PATH/'build'/'config'/'gclient_args.gni')
    if not gclient_args_path.exists():
        shutil.copyfile(Path(__file__).parent.resolve() /
                        'gclient_args.gni', gclient_args_path)


def setup_environment_variables():
    build_tool_path = SRC_PATH/'buildtools'
    os.environ['CHROMIUM_BUILDTOOLS_PATH'] = str(build_tool_path)


def build():
    gn_args = {'debug': 'is_debug=true is_component_build=false symbol_level=1',
               'release': 'is_debug=false is_component_build=false'}
    for scheme, args in gn_args.items():
        output_path = SRC_PATH/'out'/scheme
        subprocess.call(['gn', 'gen', str(output_path), '--args=%s' % args])
        if subprocess.call(['ninja', '-C', str(output_path), SDK_TARGET_NAME],
                           cwd=SRC_PATH, shell=False):
            return False
    return True


def main():
    sync()
    patch()
    create_gclient_args()
    setup_environment_variables()
    if not build():
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
