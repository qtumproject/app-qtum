/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"

#include "../globals.h"
#include "menu.h"
#include "display.h"

static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[] = {APPVERSION, "Ledger", "(c) 2023 Ledger"};

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
};

static nbgl_layoutSwitch_t switches[1];

static void controls_call_back(int token, uint8_t index) {
    (void) index;
    uint8_t value;
    switch (token) {
        case BLIND_SIGNING_TOKEN:
            value = (N_storage.dataAllowed ? 0 : 1);
            nvm_write((void*) &N_storage.dataAllowed, (void*) &value, sizeof(uint8_t));
            break;
    }
}

static bool navigation_cb(uint8_t page, nbgl_pageContent_t* content) {
    uint8_t index = 0;
    switch (page) {
        case 0:
            content->type = INFOS_LIST;
            content->infosList.nbInfos = 3;
            content->infosList.infoTypes = (const char**) infoTypes;
            content->infosList.infoContents = (const char**) infoContents;
            break;

        case 1:
            switches[index++] =
                (nbgl_layoutSwitch_t){.initState = N_storage.dataAllowed ? ON_STATE : OFF_STATE,
                                      .text = "Blind signing",
                                      .subText = "Enable transaction blind\nsigning",
                                      .token = BLIND_SIGNING_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};
            content->type = SWITCHES_LIST;
            content->switchesList.nbSwitches = index;
            content->switchesList.switches = (nbgl_layoutSwitch_t*) switches;
            break;

        default:
            return false;
            break;
    }
    return true;
}

static void exit(void) {
    os_sched_exit(-1);
}

void ui_menu_main_flow_bitcoin(void) {
    nbgl_useCaseHome("Qtum", &C_Bitcoin_64px, NULL, false, ui_menu_about, exit);
}

void ui_menu_main_flow_bitcoin_testnet(void) {
    nbgl_useCaseHome("Qtum Test",
                     &C_Bitcoin_64px,
                     "This app enables signing\ntransactions on all the Qtum\ntest networks.",
                     false,
                     ui_menu_about,
                     exit);
}

void ui_menu_about(void) {
    nbgl_useCaseSettings("Qtum", 0, 2, false, ui_menu_main, navigation_cb, controls_call_back);
}

void ui_menu_about_testnet(void) {
    nbgl_useCaseSettings("Qtum Test", 0, 2, false, ui_menu_main, navigation_cb, controls_call_back);
}

void settings_call_back(void) {
    set_ux_flow_response(N_storage.dataAllowed);
}

void ui_menu_settings(void) {
    nbgl_useCaseSettings("Qtum",
                         1,
                         2,
                         false,
                         settings_call_back,
                         navigation_cb,
                         controls_call_back);
}
#endif  // HAVE_NBGL
