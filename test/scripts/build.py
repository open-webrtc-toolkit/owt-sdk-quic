# Copyright (C) <2020> Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

'''Script for build in continuous integration environment.

It synchronizes code, builds SDK and creates a zip file for the SDK. Please run
this script with python 3.4 or newer on Ubuntu 18.04 or Windows 10 20H2.

It's expected to be ran on continuous integration machines and nightly build
machines.
'''

import os
import subprocess
import sys
from pathlib import Path
import shutil
import zipfile
import argparse

SRC_PATH = Path(__file__).resolve().parents[3]
PATCH_PATH = SRC_PATH/'owt'/'web_transport'/'patches'
PACKAGE_PATH = SRC_PATH.parent/'packages'
SDK_TARGETS = ['owt_web_transport']
TEST_TARGETS = ['owt_web_transport_tests']
TEST_TARGETS_WIN = ['owt_web_transport_dll_tests']
PATCH_LIST = [
    ('0001-Add-owt_web_transport-to-BUILD.gn.patch', SRC_PATH)
]
GIT_BIN = 'git.bat' if sys.platform == 'win32' else 'git'

def sync():
    gclient_bin = 'gclient.bat' if sys.platform == 'win32' else 'gclient'
    if subprocess.call([gclient_bin, 'sync', '--reset'], cwd=SRC_PATH, shell=False):
        return False
    return True


def patch():
    for file_name, path in PATCH_LIST:
        if(subprocess.call([GIT_BIN, 'am', str(PATCH_PATH/file_name)], cwd=path)) != 0:
            subprocess.call([GIT_BIN, 'am', '--skip'], cwd=path)


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
    gn_bin = 'gn.bat' if sys.platform == 'win32' else 'gn'
    test_targets_on_this_platform = TEST_TARGETS
    if sys.platform == 'win32':
        test_targets_on_this_platform.extend(TEST_TARGETS_WIN)
    targets = SDK_TARGETS+test_targets_on_this_platform
    for scheme, args in gn_args.items():
        output_path = SRC_PATH/'out'/scheme
        subprocess.call([gn_bin, 'gen', str(output_path), '--args=%s' % args])
        if subprocess.call(['ninja', '-C', str(output_path)]+targets,
                           cwd=SRC_PATH, shell=False):
            return False
        for test_target in test_targets_on_this_platform:
            test_path = output_path / \
                (test_target + '.exe') if sys.platform == 'win32' else output_path/test_target
            run_test = subprocess.run([test_path])
            if run_test.returncode != 0:
                return False
    return True


def pack():
    hash = subprocess.check_output(
        [GIT_BIN, 'rev-parse', 'HEAD'], cwd=SRC_PATH/'owt').strip().decode('utf-8')
    path = PACKAGE_PATH/hash
    if Path.exists(path):
        shutil.rmtree(path)
    Path.mkdir(path, parents=True)

    def pack_headers(package_root):
        shutil.copytree(SRC_PATH/'owt'/'web_transport' / 'sdk' /
                        'api', package_root/'include')

    def pack_binaries(package_root):
        file_names = []
        for sdk_target in SDK_TARGETS:
            if sys.platform == 'win32':
                file_names.extend([sdk_target+'.dll', sdk_target+'.dll.lib'])
            elif sys.platform == 'linux':
                file_names.extend(['lib'+sdk_target+'.so'])
        for scheme in ['debug', 'release']:
            Path.mkdir(package_root/'bin'/scheme, parents=True)
            for file_name in file_names:
                shutil.copyfile(SRC_PATH/'out'/scheme / file_name,
                                package_root/'bin'/scheme/file_name)

    def pack_third_party_licenses(package_root):
        Path.mkdir(package_root/'docs')
        shutil.copyfile(SRC_PATH/'owt'/'web_transport'/'docs' /
                        'third_party_licenses.txt', package_root/'docs'/'third_party_licenses.txt')

    def zip_sdk(package_root, hash):
        with zipfile.ZipFile(PACKAGE_PATH/(hash+'.zip'), 'w', zipfile.ZIP_DEFLATED) as package_zip:
            for root, dirs, files in os.walk(package_root):
                for file in files:
                    file_path = Path(root)/file
                    relative_path = file_path.relative_to(package_root)
                    package_zip.write(file_path, relative_path)

    def delete_dir(package_root):
        shutil.rmtree(package_root)


    pack_headers(path)
    pack_binaries(path)
    pack_third_party_licenses(path)
    zip_sdk(path, hash)
    delete_dir(path)


def checkout(ref):
    subprocess.call(
        [GIT_BIN, 'fetch', 'origin', ref, '&&', GIT_BIN, 'checkout', 'FETCH_HEAD'], cwd=SRC_PATH/'owt')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ref', help='Refs to be tested against.')
    opts=parser.parse_args()
    if opts.ref:
        checkout(opts.ref)
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
