/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-sctp.h"

#include "mme-event.h"
#include "mme-sm.h"

#include "sgsap-path.h"

int sgsap_open(void)
{
    mme_vlr_t *vlr = NULL;

    ogs_list_for_each(&mme_self()->vlr_list, vlr) {
        mme_event_t e;

        memset(&e, 0, sizeof(e));
        e.vlr = vlr;

        ogs_fsm_init(&vlr->sm, sgsap_state_initial, sgsap_state_final, &e);
    }

    return OGS_OK;
}

void sgsap_close(void)
{
    mme_vlr_t *vlr = NULL;

    ogs_list_for_each(&mme_self()->vlr_list, vlr) {
        mme_event_t e;
        memset(&e, 0, sizeof(e));
        e.vlr = vlr;

        ogs_fsm_fini(&vlr->sm, &e);
    }
}

int sgsap_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    int sent;

    ogs_assert(sock);
    ogs_assert(pkbuf);

    sent = ogs_sctp_sendmsg(sock, pkbuf->data, pkbuf->len,
            NULL, OGS_SCTP_SGSAP_PPID, stream_no);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_sctp_sendmsg(len:%d,ssn:%d) error (%d:%s)",
                pkbuf->len, stream_no, errno, strerror(errno));
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ogs_pkbuf_free(pkbuf);
    return OGS_OK;
}

int sgsap_send_to_vlr_with_sid(
        mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    ogs_sock_t *sock = NULL;;

    ogs_assert(vlr);
    ogs_assert(pkbuf);
    sock = vlr->sock;
    ogs_assert(sock);

    ogs_debug("    StreamNO[%d] VLR-IP[%s]",
            stream_no, ogs_sockaddr_to_string_static(vlr->sa_list));

    return sgsap_send(sock, pkbuf, stream_no);
}

int sgsap_send_to_vlr(mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf)
{
    mme_csmap_t *csmap = NULL;
    mme_vlr_t *vlr = NULL;

    ogs_assert(pkbuf);

    ogs_assert(mme_ue);
    csmap = mme_ue->csmap;
    ogs_assert(csmap);
    vlr = csmap->vlr;
    ogs_assert(vlr);

    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                ogs_plmn_id_hexdump(&csmap->tai.nas_plmn_id), csmap->tai.tac);
    ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                ogs_plmn_id_hexdump(&csmap->lai.nas_plmn_id), csmap->lai.lac);

    return sgsap_send_to_vlr_with_sid(vlr, pkbuf, mme_ue->vlr_ostream_id);
}

int sgsap_send_location_update_request(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] LOCATION-UPDATE-REQUEST");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_location_update_request(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_location_update_request() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_tmsi_reallocation_complete(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] TMSI-REALLOCATION-COMPLETE");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_tmsi_reallocation_complete(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_tmsi_reallocation_complete() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_ue_activity_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] Tx UE-ACTIVITY-IND");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_ue_activity_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_tmsi_reallocation_complete() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_detach_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    pkbuf = sgsap_build_detach_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_detach_indication() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_mo_csfb_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] MO-CSFB-INDICATION");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_mo_csfb_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_mo_csfb_indication() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_paging_reject(mme_ue_t *mme_ue, uint8_t sgs_cause)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] PAGING-REJECT");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_paging_reject(
                &mme_ue->nas_mobile_identity_imsi,
                SGSAP_IE_IMSI_LEN, sgs_cause);
    if (!pkbuf) {
        ogs_error("sgsap_build_paging_reject() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_service_request(mme_ue_t *mme_ue, uint8_t emm_mode)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] SERVICE-REQUEST");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_debug("    SERVICE_INDICATOR[%d]", mme_ue->service_indicator);
    ogs_debug("    EMM_MODE[%d]", emm_mode);

    pkbuf = sgsap_build_service_request(mme_ue, emm_mode);
    if (!pkbuf) {
        ogs_error("sgsap_build_service_request() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_reset_ack(mme_vlr_t *vlr)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(vlr);

    ogs_debug("[SGSAP] RESET-ACK");

    pkbuf = sgsap_build_reset_ack(vlr);
    if (!pkbuf) {
        ogs_error("sgsap_build_reset_ack() failed");
        return OGS_ERROR;
    }
    rv =  sgsap_send_to_vlr_with_sid(vlr, pkbuf, 0);
    ogs_expect(rv == OGS_OK);

    return rv;
}

/*
 * MO SMS (3GPP TS 24.011): if the TP-DA has at least 10 digits after a leading
 * "91" (i.e. 12 or more digits in total), strip the "91" in place.
 *
 * Container: [0]=PD(9) [1]=CP-DATA(1) [2]=CP len [3]=RP-MTI(0) [4]=RP-MR
 *   [5]=RP-OA len(0) [6]=RP-DA len +RP-DA, then RP-UD len, then TPDU:
 *   [0]=first octet [1]=TP-MR [2]=TP-DA digits [3]=TOA [4..]=digits (BCD)
 * Removing the first digit byte (0x19 = "9","1") drops exactly two digits.
 */

static void sgsap_strip_91_from_mo_sms(ogs_nas_eps_message_container_t *c)
{
    uint8_t *b = c->buffer;
    uint32_t l = c->length, rp_ud, tp;

    if (l < 8 || (b[0] & 0x0f) != 0x09 || b[1] != 0x01 ||
        b[2] != l - 3 || b[3] != 0x00 || b[5] != 0x00) return;

    rp_ud = 7 + (uint32_t)b[6];
    if (rp_ud >= l || b[rp_ud] != l - rp_ud - 1) return;

    tp = rp_ud + 1;
    if (l < tp + 5 || (b[tp] & 0x03) != 0x01) return;          /* SMS-SUBMIT */
    if (b[tp + 2] < 12 || b[tp + 4] != 0x19) return;           /* >=12 digits, "91" */
    if (l < tp + 4 + (uint32_t)(b[tp + 2] + 1) / 2) return;    /* digits fit */

    memmove(&b[tp + 4], &b[tp + 5], l - (tp + 5));
    b[tp + 2] -= 2;
    b[tp + 3] = 0x81;               /* unknown TON, ISDN NPI */
    b[rp_ud] -= 1;
    b[2] -= 1;
    c->length = (uint8_t)(l - 1);

    ogs_info("[SGSAP] MO SMS: removed 91 from TP-DA");
}

int sgsap_send_uplink_unitdata(mme_ue_t *mme_ue,
        ogs_nas_eps_message_container_t *nas_message_container)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);
    ogs_assert(nas_message_container);
	
	sgsap_strip_91_from_mo_sms(nas_message_container);

    ogs_debug("[SGSAP] UPLINK-UNITDATA");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_log_hexdump(OGS_LOG_DEBUG,
            nas_message_container->buffer, nas_message_container->length);

    pkbuf = sgsap_build_uplink_unidata(mme_ue, nas_message_container);
    if (!pkbuf) {
        ogs_error("sgsap_build_uplink_unidata() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgsap_send_ue_unreachable(mme_ue_t *mme_ue, uint8_t sgs_cause)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] UE-UNREACHABLE");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_debug("    CAUSE[%d]", sgs_cause);

    pkbuf = sgsap_build_ue_unreachable(mme_ue, sgs_cause);
    if (!pkbuf) {
        ogs_error("sgsap_build_ue_unreachable() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}
