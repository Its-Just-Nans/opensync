/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef OW_CONF_RSNO_H_INCLUDED
#define OW_CONF_RSNO_H_INCLUDED

#include <osw_drv.h>
#include <osw_conf.h>
#include <osw_types.h>

enum ow_conf_rsno_mode
{
    OW_CONF_RSNO_MODE_DISABLED = 0,

    /* This is intended to fulfill the definition of WFA WPA spec's WPA3
     * Compatibility Mode where, notably, RSNE contains only PSK (or only SAE
     * on 6GHz), RSNO1 contains SAE (or nothing on 6GHz), and RSNO2 contains
     * SAE-EXT for EHT/MLO.
     */
    OW_CONF_RSNO_MODE_WPA3_COMPAT,

    /* This is intended to deviate from WFA WPA spec's WPA3 Compatibility Mode
     * by pushing SAE back into RSNE by default meaning: RSNE would contain
     * PSK+SAE (or just SAE on 6GHz), RSNO1 would always be empty, and RSNO2
     * would contain SAE-EXT.
     *
     * This is technically within RSNO definition itself and should provide
     * slightly better security properties (ie not worse then WPA3 Personal
     * Transition) that many devices have been able to set up without issues.
     */
    OW_CONF_RSNO_MODE_WPA3_COMPAT_TRANSITION,
};
typedef enum ow_conf_rsno_mode ow_conf_rsno_mode_t;

const char *ow_conf_rsno_mode_to_cstr(enum ow_conf_rsno_mode mode);

ow_conf_rsno_mode_t ow_conf_rsno_mode_get(struct osw_conf_vif *vif);

void ow_conf_rsno_mutate_vif_ap(struct osw_conf_vif *osw_vif, ow_conf_rsno_mode_t mode);

void ow_conf_rsno_fix_wpa_with_state(struct osw_wpa *wpa, const struct osw_drv_vif_state_ap *ap);

#endif /* OW_CONF_RSNO_H_INCLUDED */
