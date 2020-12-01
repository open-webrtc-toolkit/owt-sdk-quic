# Copyright (C) <2020> Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

'''Script for build in continuous integration environment.

Python version required is 2.7 and higher.

Ouput lib is located in packages dir.

'''

import os
import subprocess
import sys
import shutil

SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), r'..\..\..'))
PATCH_PATH = os.path.join(SRC_PATH, r'owt\quic_transport\patches')
PACKAGE_PATH = os.path.join(SRC_PATH, r'packages')
SDK_TARGET_NAME = 'owt_quic_transport'
PATCH_LIST = [
    ('0001-Add-owt_quic_transport-to-BUILD.gn.patch', SRC_PATH)
]


def sync():
    if subprocess.call(['gclient.bat', 'sync'], cwd=SRC_PATH, shell=False):
        return False
    return True


def patch():
    for file_name, path in PATCH_LIST:
        if(subprocess.call(['git.bat', 'am', os.path.join(PATCH_PATH, file_name)], 
              shell=False, cwd=path)) != 0:
            subprocess.call(['git.bat', 'am', '--skip'], cwd=path)


def create_gclient_args():
    gclient_args_path = os.path.join(SRC_PATH, r'build\config\gclient_args.gni');
    if not os.path.exists(gclient_args_path):
        shutil.copyfile(os.path.join(Path(__file__).parent.resolve(),
                        r'gclient_args.gni'), gclient_args_path)


def setup_environment_variables():
    build_tool_path = os.path.join(SRC_PATH, r'buildtools')
    os.environ['CHROMIUM_BUILDTOOLS_PATH'] = str(build_tool_path)


def build():
    gn_args = {'debug': 'is_debug=true is_component_build=false symbol_level=1',
               'release': 'is_debug=false is_component_build=false'}
    for scheme, args in gn_args.items():
        output_path = os.path.join(SRC_PATH, r'out\%s' % scheme)
        subprocess.call(['gn.bat', 'gen', str(output_path), '--args=%s' % args])
        if subprocess.call(['ninja', '-C', str(output_path), SDK_TARGET_NAME],
                           cwd=SRC_PATH, shell=False):
            return False
    return True


def pack():
    hash = subprocess.check_output(
        ['git.bat', 'rev-parse', 'HEAD'],
            cwd=os.path.join(SRC_PATH, r'owt')).strip().decode('utf-8')
    path = os.path.join(PACKAGE_PATH, r'%s' % hash)

    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)

    def pack_headers(package_root):
        shutil.copytree(os.path.join(SRC_PATH, r'owt\quic_transport\api'),
                        os.path.join(package_root, r'include'))

    def pack_binaries(package_root):
        dll_file_name = SDK_TARGET_NAME+'.dll'
        lib_file_name = SDK_TARGET_NAME+'.dll.lib'
        for scheme in ['debug', 'release']:
            bin_path = os.path.join(package_root, r'bin\%s' % scheme)
            os.makedirs(bin_path)
            shutil.copyfile(os.path.join(SRC_PATH, r'out\%s\%s' % (scheme, dll_file_name)),
                os.path.join(package_root, r'bin\%s\%s' % (scheme, dll_file_name)))
            shutil.copyfile(os.path.join(SRC_PATH, r'out\%s\%s' % (scheme, lib_file_name)),
                os.path.join(package_root, r'bin\%s\%s' % (scheme, lib_file_name)))

    pack_headers(path)
    pack_binaries(path)
    print('Please find the package in https://example.com/%s'%hash)


def main():
    if not sync():
        return 1
    patch()
    create_gclient_args()
    setup_environment_variables()
    if not build():
        return 1
    pack()
    return 0


if __name__ == '__main__':
    sys.exit(main())
