/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdint.h>


int esp32flashGetUpdateMem(uint32_t *loc, uint32_t *size);
int esp32flashSetOtaAsCurrentImage();
int esp32flashRebootIntoOta();
