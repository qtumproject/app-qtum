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

#ifdef HAVE_BAGL
#include "os.h"
#include "ux.h"

#include "../globals.h"
#include "menu.h"

static void display_settings(const ux_flow_step_t* const start_step);
static void switch_settings_blind_signing(void);

// We have a screen with the icon and "Bitcoin is ready" for Bitcoin,
// "Bitcoin Testnet is ready" for Bitcoin Testnet.
UX_STEP_NOCB(ux_menu_ready_step_bitcoin, pnn, {&C_bitcoin_logo, "Qtum", "is ready"});
UX_STEP_NOCB(ux_menu_ready_step_bitcoin_testnet,
             pnn,
             {&C_bitcoin_logo, "Qtum Testnet", "is ready"});

UX_STEP_NOCB(ux_menu_version_step, bn, {"Version", APPVERSION});
UX_STEP_CB(ux_menu_about_step, pb, ui_menu_about(), {&C_icon_certificate, "About"});
UX_STEP_CB(ux_menu_settings_step, pb, ui_menu_settings(), {&C_icon_coggle, "Settings"});
UX_STEP_VALID(ux_menu_exit_step, pb, os_sched_exit(-1), {&C_icon_dashboard_x, "Quit"});

// FLOW for the main menu (for bitcoin):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: about submenu
// #4 screen: quit
UX_FLOW(ux_menu_main_flow_bitcoin,
        &ux_menu_ready_step_bitcoin,
        &ux_menu_version_step,
        &ux_menu_about_step,
        &ux_menu_settings_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

// FLOW for the main menu (for bitcoin testnet):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: about submenu
// #4 screen: quit
UX_FLOW(ux_menu_main_flow_bitcoin_testnet,
        &ux_menu_ready_step_bitcoin_testnet,
        &ux_menu_version_step,
        &ux_menu_about_step,
        &ux_menu_settings_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

UX_STEP_NOCB(ux_menu_info_step, bn, {"Qtum App", "(c) 2023 Ledger"});
UX_STEP_CB(ux_menu_back_step, pb, ui_menu_main(), {&C_icon_back, "Back"});

// FLOW for the about submenu:
// #1 screen: app info
// #2 screen: back button to main menu
UX_FLOW(ux_menu_about_flow, &ux_menu_info_step, &ux_menu_back_step, FLOW_LOOP);

void ui_menu_main_flow_bitcoin(void) {
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    ux_flow_init(0, ux_menu_main_flow_bitcoin, NULL);
}

void ui_menu_main_flow_bitcoin_testnet(void) {
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    ux_flow_init(0, ux_menu_main_flow_bitcoin_testnet, NULL);
}

void ui_menu_about(void) {
    ux_flow_init(0, ux_menu_about_flow, NULL);
}

void ui_menu_settings(void) {
    display_settings(NULL);
}

#define ENABLED_STR   "Enabled"
#define DISABLED_STR  "Disabled"
#define BUF_INCREMENT (MAX(strlen(ENABLED_STR), strlen(DISABLED_STR)) + 1)
char strings[BUF_INCREMENT];
#define SETTING_BLIND_SIGNING_STATE strings
#define BOOL_TO_STATE_STR(b)        (b ? ENABLED_STR : DISABLED_STR)

// clang-format off
UX_STEP_CB(
    ux_settings_flow_blind_signing_step,
#ifdef TARGET_NANOS
    bnnn_paging,
#else
    bnnn,
#endif
    switch_settings_blind_signing(),
    {
#ifdef TARGET_NANOS
      .title = "Blind signing",
      .text =
#else
      "Blind signing",
      "Transaction",
      "blind signing",
#endif
      SETTING_BLIND_SIGNING_STATE
    });

UX_FLOW(ux_settings_flow,
        &ux_settings_flow_blind_signing_step, &ux_menu_back_step, FLOW_LOOP);

static void display_settings(const ux_flow_step_t* const start_step) {
    strlcpy(SETTING_BLIND_SIGNING_STATE, BOOL_TO_STATE_STR(N_storage.dataAllowed), BUF_INCREMENT);

    ux_flow_init(0, ux_settings_flow, start_step);
}

static void toggle_setting(volatile bool* setting, const ux_flow_step_t* ui_step) {
    bool value = !*setting;
    nvm_write((void*) setting, (void*) &value, sizeof(value));
    display_settings(ui_step);
}

static void switch_settings_blind_signing(void) {
    toggle_setting(&N_storage.dataAllowed, &ux_settings_flow_blind_signing_step);
}

#endif  // HAVE_BAGL
