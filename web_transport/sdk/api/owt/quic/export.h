/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OWT_QUIC_EXPORT_H_
#define OWT_QUIC_EXPORT_H_

// Defines OWT_EXPORT so that functionality implemented by the net module can
// be exported to consumers, and OWT_EXPORT_PRIVATE that allows unit tests to
// access features not intended to be used directly by real consumers.

#if defined(WIN32)

#ifdef OWT_QUIC_LIBRARY_IMPL
#define OWT_EXPORT __declspec(dllexport)
#define OWT_EXPORT_PRIVATE __declspec(dllexport)
#else
#define OWT_EXPORT __declspec(dllimport)
#define OWT_EXPORT_PRIVATE __declspec(dllimport)
#endif

#else  // defined(WIN32)

#define OWT_EXPORT __attribute__((visibility("default")))
#define OWT_EXPORT_PRIVATE __attribute__((visibility("default")))

#endif

#endif  // OWT_QUIC_EXPORT_H_