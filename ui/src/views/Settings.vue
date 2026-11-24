<!--
  Copyright (C) 2026 Startapp Srl, derived from work Copyright (C) 2022 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getConfiguration">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-configuration')"
          :description="error.getConfiguration"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-form @submit.prevent="configureModule">
            <cv-text-input
              :label="$t('settings.startconnect_fqdn')"
              placeholder="connect.example.org"
              v-model.trim="host"
              class="mg-bottom"
              :invalid-message="$t(error.host)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="host"
            >
            </cv-text-input>
            <NsToggle
              value="letsEncrypt"
              :label="core.$t('apps_lets_encrypt.request_https_certificate')"
              v-model="isLetsEncryptEnabled"
              :disabled="stillLoading"
              class="mg-bottom"
            >
              <template #tooltip>
                <div class="mg-bottom-sm">
                  {{ core.$t("apps_lets_encrypt.lets_encrypt_tips") }}
                </div>
                <div class="mg-bottom-sm">
                  <cv-link @click="goToCertificates">
                    {{ core.$t("apps_lets_encrypt.go_to_tls_certificates") }}
                  </cv-link>
                </div>
              </template>
              <template slot="text-left">{{
                $t("settings.disabled")
              }}</template>
              <template slot="text-right">{{
                $t("settings.enabled")
              }}</template>
            </NsToggle>
            <cv-row
              v-if="isLetsEncryptCurrentlyEnabled && !isLetsEncryptEnabled"
            >
              <cv-column>
                <NsInlineNotification
                  kind="warning"
                  :title="
                    core.$t('apps_lets_encrypt.lets_encrypt_disabled_warning')
                  "
                  :description="
                    core.$t(
                      'apps_lets_encrypt.lets_encrypt_disabled_warning_description',
                      {
                        node: this.status.node_ui_name
                          ? this.status.node_ui_name
                          : this.status.node,
                      }
                    )
                  "
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <cv-toggle
              value="httpToHttps"
              :label="$t('settings.http_to_https')"
              v-model="isHttpToHttpsEnabled"
              :disabled="loading.getConfiguration || loading.configureModule"
              class="mg-bottom"
            >
              <template slot="text-left">{{
                $t("settings.disabled")
              }}</template>
              <template slot="text-right">{{
                $t("settings.enabled")
              }}</template>
            </cv-toggle>
                        
              <!-- LDAP domain -->
            <NsComboBox              
              v-model.trim="ldap_domain"
              :autoFilter="true"
              :autoHighlight="true"
              :title="$t('settings.ldap_domain')"
              :label="$t('settings.choose_ldap_domain')"
              :options="domains_list"
              :acceptUserInput="false"
              :showItemType="true"
              :invalid-message="$t(error.ldap_domain)"
              :disabled="loading.getConfiguration || loading.configureModule"
              tooltipAlignment="start"
              tooltipDirection="top"
              ref="ldap_domain"
            >
              <template slot="tooltip">
                {{ $t("settings.choose_the_ldap_domain_to_use") }}
              </template>
            </NsComboBox>
            <cv-text-input
              :label="$t('settings.admin_group')"
              :helper-text="$t('settings.admin_group_helper')"
              v-model.trim="admin_group"
              class="mg-bottom"
              :invalid-message="$t(error.admin_group)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="admin_group"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.audit_retention_days')"
              :helper-text="$t('settings.audit_retention_days_helper')"
              v-model.number="audit_retention_days"
              type="number"
              min="30"
              max="3650"
              class="mg-bottom"
              :invalid-message="$t(error.audit_retention_days)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="audit_retention_days"
            >
            </cv-text-input>
            <!-- RustDesk (facoltativo) -->
            <h4 class="mg-bottom-sm">{{ $t("settings.rustdesk_title") }}</h4>
            <p class="mg-bottom helper">{{ $t("settings.rustdesk_description") }}</p>
            <cv-text-input
              :label="$t('settings.rustdesk_id_server')"
              :helper-text="$t('settings.rustdesk_id_server_helper')"
              placeholder="rustdesk.example.org"
              v-model.trim="rustdesk.id_server"
              class="mg-bottom"
              :invalid-message="$t(error.rustdesk_id_server)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_id_server"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.rustdesk_relay_server')"
              :helper-text="$t('settings.rustdesk_relay_server_helper')"
              v-model.trim="rustdesk.relay_server"
              class="mg-bottom"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_relay_server"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.rustdesk_api_server')"
              placeholder="https://rustdesk.example.org"
              v-model.trim="rustdesk.api_server"
              class="mg-bottom"
              :invalid-message="$t(error.rustdesk_api_server)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_api_server"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.rustdesk_key')"
              :helper-text="$t('settings.rustdesk_key_helper')"
              v-model.trim="rustdesk.key"
              class="mg-bottom"
              :invalid-message="$t(error.rustdesk_key)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_key"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.rustdesk_api_user')"
              :helper-text="$t('settings.rustdesk_api_user_helper')"
              v-model.trim="rustdesk.api_user"
              class="mg-bottom"
              autocomplete="off"
              :invalid-message="$t(error.rustdesk_api_user)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_api_user"
            >
            </cv-text-input>
            <cv-text-input
              :label="$t('settings.rustdesk_api_password')"
              :helper-text="rustdesk.password_set ? $t('settings.rustdesk_api_password_set') : $t('settings.rustdesk_api_password_helper')"
              v-model="rustdesk.api_password"
              type="password"
              :password-hide-label="$t('settings.hide')"
              :password-show-label="$t('settings.show')"
              class="mg-bottom"
              autocomplete="new-password"
              :invalid-message="$t(error.rustdesk_api_password)"
              :disabled="loading.getConfiguration || loading.configureModule"
              ref="rustdesk_api_password"
            >
            </cv-text-input>
            <cv-row v-if="error.configureModule">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="$t('action.configure-module')"
                  :description="error.configureModule"
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <cv-row v-if="error.getStatus">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="$t('action.get-status')"
                  :description="error.getStatus"
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <cv-row v-if="validationErrorDetails.length">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="
                    core.$t('apps_lets_encrypt.cannot_obtain_certificate')
                  "
                  :showCloseButton="false"
                >
                  <template #description>
                    <div class="flex flex-col gap-2">
                      <div
                        v-for="(detail, index) in validationErrorDetails"
                        :key="index"
                      >
                        {{ detail }}
                      </div>
                    </div>
                  </template>
                </NsInlineNotification>
              </cv-column>
            </cv-row>
            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="loading.getConfiguration || loading.configureModule"
              >{{ $t("settings.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import to from "await-to-js";
import { mapState } from "vuex";
import {
  QueryParamService,
  UtilService,
  TaskService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";

export default {
  name: "Settings",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "settings",
      },
      status: {},
      validationErrorDetails: [],
      urlCheckInterval: null,
      host: "",
      isLetsEncryptEnabled: false,
      isLetsEncryptCurrentlyEnabled: false,
      isHttpToHttpsEnabled: true,
      ldap_domain: "",
      admin_group: "domain admins",
      audit_retention_days: 365,
      domains_list: [],
      // La password di rustdesk-api non arriva mai dal server: vuota = invariata
      rustdesk: {
        id_server: "",
        relay_server: "",
        api_server: "",
        key: "",
        api_user: "",
        api_password: "",
        password_set: false,
      },
      loading: {
        getConfiguration: false,
        configureModule: false,
        getStatus: false,
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        host: "",
        lets_encrypt: "",
        http2https: "",
        ldap_domain: "",
        admin_group: "",
        audit_retention_days: "",
        rustdesk_id_server: "",
        rustdesk_api_server: "",
        rustdesk_key: "",
        rustdesk_api_user: "",
        rustdesk_api_password: "",
        getStatus: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    stillLoading() {
      return (
        this.loading.getConfiguration ||
        this.loading.configureModule ||
        this.loading.getStatus
      );
    },
  },
  created() {
    this.getConfiguration();
    this.getStatus();
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  methods: {
    goToCertificates() {
      this.core.$router.push("/settings/tls-certificates");
    },
    async getStatus() {
      this.loading.getStatus = true;
      this.error.getStatus = "";
      const taskAction = "get-status";
      const eventId = this.getUuid();
      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getStatusAborted
      );
      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getStatusCompleted
      );
      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.getStatus = this.getErrorMessage(err);
        this.loading.getStatus = false;
        return;
      }
    },
    getStatusAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.getStatus = this.$t("error.generic_error");
      this.loading.getStatus = false;
    },
    getStatusCompleted(taskContext, taskResult) {
      this.status = taskResult.output;
      this.loading.getStatus = false;
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getConfigurationAborted
      );

      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getConfigurationCompleted
      );

      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];

      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.getConfiguration = this.getErrorMessage(err);
        this.loading.getConfiguration = false;
        return;
      }
    },
    getConfigurationAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.getConfiguration = this.$t("error.generic_error");
      this.loading.getConfiguration = false;
    },
    getConfigurationCompleted(taskContext, taskResult) {
      const config = taskResult.output;
      this.host = config.host;
      this.isLetsEncryptEnabled = config.lets_encrypt;
      this.isLetsEncryptCurrentlyEnabled = config.lets_encrypt;
      this.isHttpToHttpsEnabled = config.http2https;
      this.domains_list = config.domains_list;
      this.admin_group = config.admin_group;
      this.audit_retention_days = config.audit_retention_days;
      const rd = config.rustdesk || {};
      this.rustdesk = {
        id_server: rd.id_server || "",
        relay_server: rd.relay_server && rd.relay_server !== rd.id_server ? rd.relay_server : "",
        api_server: rd.api_server || "",
        key: rd.key || "",
        api_user: rd.api_user || "",
        api_password: "",
        password_set: Boolean(rd.api_password_set),
      };
      // this.ldap_domain = config.ldap_domain;
      // force to reload value after dom update
      this.$nextTick(() => {
        this.ldap_domain = config.ldap_domain;
      });

      this.loading.getConfiguration = false;
      this.focusElement("host");
    },
    validateConfigureModule() {
      this.clearErrors(this);
      this.validationErrorDetails = [];

      let isValidationOk = true;
      if (!this.host) {
        this.error.host = "common.required";

        if (isValidationOk) {
          this.focusElement("host");
        }
        isValidationOk = false;
      }
      
      if (!this.ldap_domain) {
        this.error.ldap_domain = "common.required";
        if (isValidationOk) {
          this.focusElement("ldap_domain");
        }
        isValidationOk = false;
      }
      if (!this.admin_group) {
        this.error.admin_group = "common.required";
        if (isValidationOk) {
          this.focusElement("admin_group");
        }
        isValidationOk = false;
      }

      // RustDesk: facoltativo, ma se si indica il server servono chiave e accesso coerenti
      const rd = this.rustdesk;
      const fail = (field, message) => {
        this.error[field] = message;
        if (isValidationOk) {
          this.focusElement(field);
        }
        isValidationOk = false;
      };
      if (rd.id_server || rd.api_server || rd.key || rd.api_user) {
        if (!rd.id_server) {
          fail("rustdesk_id_server", "common.required");
        }
        if (!rd.key) {
          fail("rustdesk_key", "common.required");
        }
      }
      if (rd.api_server && !rd.api_server.startsWith("https://")) {
        fail("rustdesk_api_server", "settings.rustdesk_https_required");
      }
      if (rd.api_user && !rd.api_server) {
        fail("rustdesk_api_server", "settings.rustdesk_api_server_required");
      }
      if (rd.api_user && !rd.password_set && !rd.api_password) {
        fail("rustdesk_api_password", "common.required");
      }

      return isValidationOk;
    },
    configureModuleValidationFailed(validationErrors) {
      this.loading.configureModule = false;
      let focusAlreadySet = false;
      for (const validationError of validationErrors) {
        const param = validationError.parameter;
        if (validationError.details) {
          // show inline error notification with details
          this.validationErrorDetails = validationError.details
            .split("\n")
            .filter((detail) => detail.trim() !== "");
        } else {
          // set i18n error message
          this.error[param] = this.$t("settings." + validationError.error);
          if (!focusAlreadySet) {
            this.focusElement(param);
            focusAlreadySet = true;
          }
        }
      }
    },
    async configureModule() {
      const isValidationOk = this.validateConfigureModule();
      if (!isValidationOk) {
        return;
      }

      this.loading.configureModule = true;
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.configureModuleAborted
      );

      // register to task validation
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.configureModuleValidationFailed
      );

      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.configureModuleCompleted
      );
      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            host: this.host,
            lets_encrypt: this.isLetsEncryptEnabled,
            http2https: this.isHttpToHttpsEnabled,
            ldap_domain: this.ldap_domain,
            admin_group: this.admin_group,
            audit_retention_days: Number(this.audit_retention_days),
            rustdesk: this.rustdeskPayload(),
          },
          extra: {
            title: this.$t("settings.instance_configuration", {
              instance: this.instanceName,
            }),
            description: this.$t("settings.configuring"),
            eventId,
          },
        })
      );
      const err = res[0];

      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.configureModule = this.getErrorMessage(err);
        this.loading.configureModule = false;
        return;
      }
    },
    rustdeskPayload() {
      const rd = this.rustdesk;
      const payload = {
        id_server: rd.id_server,
        relay_server: rd.relay_server,
        api_server: rd.api_server,
        key: rd.key,
        api_user: rd.api_user,
      };
      // Password omessa = invariata; senza utente si cancella
      if (rd.api_password) {
        payload.api_password = rd.api_password;
      } else if (!rd.api_user) {
        payload.api_password = "";
      }
      return payload;
    },
    configureModuleAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.configureModule = this.$t("error.generic_error");
      this.loading.configureModule = false;
    },
    configureModuleCompleted() {
      this.loading.configureModule = false;

      // reload configuration
      this.getConfiguration();
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}

.mg-bottom-sm {
  margin-bottom: $spacing-03;
}

.helper {
  color: $text-02;
  max-width: 38rem;
}

.maxwidth {
  max-width: 38rem;
}
</style>
