/**
IcyQue - an ICQ replacement plugin for Pidgin
Copyright (C) 2018-2019 Eion Robb

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <glib.h>
#include <purple.h>
#include <string.h>

#include <http.h>
#include "purplecompat.h"

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#define ICQ_EVENTS      "myInfo,presence,buddylist,typing,hiddenChat,hist,mchat,sentIM,imState,dataIM,offlineIM,userAddedToBuddyList,service,lifestream,apps,permitDeny,replace,diff" //webrtcMsg
#define ICQ_PRESENCE_FIELDS    "quiet,ssl,abFriendly,role,capabilities,role,abPhones,aimId,autoAddition,friendly,largeIconId,lastseen,mute,pending,state,eventType,seqNum,displayId,friendlyName,userType,statusMsg,statusTime,buddyIcon,abContactName,abPhones,official"
#define ICQ_ASSERT_CAPS "094613564C7F11D18222444553540000,0946135A4C7F11D18222444553540000,0946135B4C7F11D18222444553540000,0946135D4C7F11D18222444553540000,0946135C4C7F11D18222444553540000,094613574C7F11D18222444553540000,094613504C7F11D18222444553540000,094613514C7F11D18222444553540000,094613534C7F11D18222444553540000,0946135E4C7F11D18222444553540000,094613544C7F11D18222444553540000,0946135F4C7F11D18222444553540000"
#define ICQ_API_SERVER        "https://api.icq.net"
#define ICQ_RAPI_SERVER       "https://rapi.icq.net"
#define ICQ_DEVID             "ao1mAegmj4_7xQOy"

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif



#include <json-glib/json-glib.h>

// Suppress overzealous json-glib 'critical errors'
#define json_object_has_member(JSON_OBJECT, MEMBER) \
	(JSON_OBJECT ? json_object_has_member(JSON_OBJECT, MEMBER) : FALSE)
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)

#define json_array_get_length(JSON_ARRAY) \
	(JSON_ARRAY ? json_array_get_length(JSON_ARRAY) : 0)

static gchar *
json_object_to_string(JsonObject *obj)
{
	JsonNode *node;
	gchar *str;
	JsonGenerator *generator;

	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, obj);

	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, NULL);
	g_object_unref(generator);
	json_node_free(node);

	return str;
}


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;

	GHashTable *cookie_table;
	GHashTable *user_ids;
	gchar *session_key;
	gchar *token;
	gchar *aimsid;

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gchar *device_id;
	gint64 last_message_timestamp;
	GHashTable *sent_messages_hash;
	
	gchar *sms_trans_id;
	
	// ICQ API
	guint heartbeat_timeout;
	PurpleHttpKeepalivePool *keepalive_pool;
	gchar *last_fetchBaseURL;
	
	// RAPI (Robusto API)
	gint64 server_time_offset;
	gchar *robusto_token;
	gint64 robusto_client_id;
	guint64 robusto_request_id;
} IcyQueAccount;


typedef void (*IcyQueProxyCallbackFunc)(IcyQueAccount *ia, JsonObject *obj, gpointer user_data);

typedef struct {
	IcyQueAccount *ia;
	IcyQueProxyCallbackFunc callback;
	gpointer user_data;
} IcyQueProxyConnection;

static int
gc_hmac_sha256(const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf)
{
#if PURPLE_VERSION_CHECK(3, 0, 0)
	GHmac *hmac;
	gsize digest_len = 32;
	
	hmac = g_hmac_new(G_CHECKSUM_SHA256, key, keylen);
	g_hmac_update(hmac, in, inlen);
	g_hmac_get_digest(hmac, resbuf, &digest_len);
	g_hmac_unref(hmac);
	
#else
	PurpleCipherContext *hmac;
	
	hmac = purple_cipher_context_new_by_name("hmac", NULL);

	purple_cipher_context_set_option(hmac, "hash", "sha256");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, keylen);
	purple_cipher_context_append(hmac, (guchar *)in, inlen);
	purple_cipher_context_digest(hmac, 32, resbuf, NULL);
	purple_cipher_context_destroy(hmac);
	
#endif
	
	return 1;
}


gchar *
icq_generate_signature(const gchar *data, const gchar *session)
{
	purple_debug_info("icyque", "Signature: {%s}, Session: {%s}\n", data, session);
	static guchar sig[33];

	gc_hmac_sha256(session, strlen(session), data, strlen(data), sig);
	sig[32] = '\0';
	
	return g_base64_encode(sig, 32);
}

gchar *
icq_get_url_sign(IcyQueAccount *ia, gboolean is_post, const gchar *url, const gchar *data)
{
	GString *hash_data = g_string_new(NULL);
	gchar *ret;
	
	g_string_append(hash_data, is_post ? "POST" : "GET");
	g_string_append_c(hash_data, '&');
	g_string_append(hash_data, purple_url_encode(url));
	g_string_append_c(hash_data, '&');
	g_string_append(hash_data, purple_url_encode(data));

	ret = icq_generate_signature(hash_data->str, ia->session_key);
	g_string_free(hash_data, TRUE);
	
    return ret;
}

static JsonObject*
icq_generate_robusto_request(IcyQueAccount *ia, const gchar* method, JsonObject* params)
{
	JsonObject *robustoRequest = json_object_new();
	
	json_object_set_string_member(robustoRequest, "authToken", ia->robusto_token);
	json_object_set_string_member(robustoRequest, "method", method);
	
	GString *request_id = g_string_new(NULL);
	g_string_append_printf(request_id, "%lu-%ld", ia->robusto_request_id++, time(NULL) - ia->server_time_offset);
	json_object_set_string_member(robustoRequest, "reqId", request_id->str);
	g_string_free(request_id, TRUE);
	
	if(ia->robusto_client_id >= 0) {
		json_object_set_int_member(robustoRequest, "clientId", ia->robusto_client_id);
	}
	
	json_object_set_object_member(robustoRequest, "params", params);
	return robustoRequest;
}

/*static gint64
to_int(const gchar *id)
{
	return id ? g_ascii_strtoll(id, NULL, 10) : 0;
}

static gchar *
from_int(gint64 id)
{
	return g_strdup_printf("%" G_GINT64_FORMAT, id);
}*/



static void
icq_update_cookies(IcyQueAccount *ia, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;

	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur)) {
		cookie_start = cur->data;

		cookie_end = strchr(cookie_start, '=');

		if (cookie_end != NULL) {
			cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');

			if (cookie_end != NULL) {
				cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
				cookie_start = cookie_end;

				g_hash_table_replace(ia->cookie_table, cookie_name, cookie_value);
			}
		}
	}
}

static void
icq_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
icq_cookies_to_string(IcyQueAccount *ia)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ia->cookie_table, (GHFunc) icq_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
icq_response_callback(PurpleHttpConnection *http_conn,
						  PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
	const gchar *error_message = purple_http_response_get_error(response);
	const gchar *body;
	gsize body_len;
	IcyQueProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();

	conn->ia->http_conns = g_slist_remove(conn->ia->http_conns, http_conn);

	icq_update_cookies(conn->ia, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;

	if (body == NULL && error_message != NULL) {
		/* connection error - unresolvable dns name, non existing server */
		gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
		purple_connection_error(conn->ia->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
		g_free(error_msg_formatted);
		g_free(conn);
		return;
	}

	if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
		if (conn->callback) {
			JsonObject *dummy_object = json_object_new();

			json_object_set_string_member(dummy_object, "body", body);
			json_object_set_int_member(dummy_object, "len", body_len);
			g_dataset_set_data(dummy_object, "raw_body", (gpointer) body);

			conn->callback(conn->ia, dummy_object, conn->user_data);

			g_dataset_destroy(dummy_object);
			json_object_unref(dummy_object);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);

		purple_debug_misc("icyque", "Got response: %s\n", body);

		if (conn->callback && root != NULL) {
			conn->callback(conn->ia, json_node_get_object(root), conn->user_data);
		}
	}

	g_object_unref(parser);
	g_free(conn);
}

static void
icq_fetch_url_with_method(IcyQueAccount *ia, const gchar *method, const gchar *url, const gchar *postdata, IcyQueProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	IcyQueProxyConnection *conn;
	gchar *cookies;
	PurpleHttpConnection *http_conn;

	account = ia->account;

	if (purple_account_is_disconnected(account)) {
		return;
	}

	conn = g_new0(IcyQueProxyConnection, 1);
	conn->ia = ia;
	conn->callback = callback;
	conn->user_data = user_data;

	cookies = icq_cookies_to_string(ia);

	if (method == NULL) {
		method = "GET";
	}

	purple_debug_info("icyque", "Fetching url %s\n", url);


	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_set_method(request, method);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "Cookie", cookies);
	purple_http_request_set_timeout(request, 59);

	if (postdata) {
		if (strstr(url, "/auth/clientLogin") && strstr(postdata, "pwd")) {
			purple_debug_info("icyque", "With postdata ###PASSWORD REMOVED###\n");
		} else {
			purple_debug_info("icyque", "With postdata %s\n", postdata);
		}
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		
		purple_http_request_set_contents(request, postdata, -1);
	}
	
	purple_http_request_set_keepalive_pool(request, ia->keepalive_pool);

	http_conn = purple_http_request(ia->pc, request, icq_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL) {
		ia->http_conns = g_slist_prepend(ia->http_conns, http_conn);
	}


	g_free(cookies);
}

static PurpleGroup *
icq_get_or_create_default_group(const gchar *group_name)
{
	if (group_name == NULL) {
		group_name = "ICQ";
	}
	
	PurpleGroup *icq_group = purple_blist_find_group(group_name);

	if (!icq_group) {
		icq_group = purple_group_new(group_name);
		purple_blist_add_group(icq_group, NULL);
	}

	return icq_group;
}

static const char *
icq_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "icq";
}

static GList *
icq_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "away", _("Away"), TRUE, FALSE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_MOBILE, "mobile", _("Mobile"), TRUE, FALSE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static gchar *
icq_status_text(PurpleBuddy *buddy)
{
	const gchar *message = purple_status_get_attr_string(purple_presence_get_active_status(purple_buddy_get_presence(buddy)), "message");
	
	if (message == NULL) {
		return NULL;
	}
	
	return g_markup_printf_escaped("%s", message);
}

static void
icq_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurplePresence *presence;
	PurpleStatus *status;
	const gchar *message;
	
	g_return_if_fail(buddy != NULL);
	
	presence = purple_buddy_get_presence(buddy);
	status = purple_presence_get_active_status(presence);
	purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));
	
	message = purple_status_get_attr_string(status, "message");
	if (message != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Message"), message);
	}
}

static void
icq_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *status_id = purple_status_get_id(status); //online, mobile, away, offline
	
	gchar *uuid = purple_uuid_random();
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/presence/setState";
	
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "ts=%d&", (int)(time(NULL) - ia->server_time_offset));
	g_string_append_printf(postdata, "view=%s", purple_url_encode(status_id));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
	
	
	const gchar *message = purple_status_get_attr_string(status, "message");
	uuid = purple_uuid_random();
	postdata = g_string_new(NULL);
	url = ICQ_API_SERVER "/presence/setStatus";
	
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "statusMsg=%s&", purple_url_encode(message ? message : ""));
	g_string_append_printf(postdata, "ts=%d", (int)(time(NULL) - ia->server_time_offset));

	sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}


static void
icq_block_user(PurpleConnection *pc, const char *who)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/preference/setPermitDeny";
	
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "pdIgnore=%s&", purple_url_encode(who));
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
}

static void
icq_unblock_user(PurpleConnection *pc, const char *who)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/preference/setPermitDeny";
	
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "pdIgnoreRemove=%s&", purple_url_encode(who));
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
}

static void
icq_got_user_info(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	if (obj == NULL) {
		return;
	}
	
	JsonObject *response = json_object_get_object_member(obj, "response");
	JsonObject *data = json_object_get_object_member(response, "data");
	JsonArray *infoArray = json_object_get_array_member(data, "infoArray");
	guint len = json_array_get_length(infoArray);
	
	if (!infoArray || !len) {
		return;
	}
	
	JsonObject *info = json_array_get_object_element(infoArray, 0);
	JsonObject *profile = json_object_get_object_member(info, "profile");
	
	if (profile == NULL) {
		return;
	}
	
	const gchar *aimId = json_object_get_string_member(profile, "aimId");
	if (aimId == NULL) {
		return;
	}
	
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	
	purple_notify_user_info_add_pair_html(user_info, _("ID"), aimId);
	
	purple_notify_user_info_add_pair_html(user_info, _("First name"), 
		json_object_get_string_member(profile, "firstName"));
	purple_notify_user_info_add_pair_html(user_info, _("Last name"), 
		json_object_get_string_member(profile, "lastName"));
	purple_notify_user_info_add_pair_html(user_info, _("Gender"), 
		json_object_get_string_member(profile, "gender"));
	purple_notify_user_info_add_pair_html(user_info, _("Alias"), 
		json_object_get_string_member(profile, "friendlyName"));
	
	
	purple_notify_userinfo(ia->pc, aimId, user_info, NULL, NULL);
}

static void
icq_get_info(PurpleConnection *pc, const gchar *who)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/memberDir/get";
	gchar *uuid = purple_uuid_random();
	
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append(postdata, "infoLevel=full&");
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "t=%s&", purple_url_encode(who));
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, icq_got_user_info, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}

static void
icq_add_buddy_with_invite(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *who = purple_buddy_get_name(buddy);
	const gchar *alias = purple_buddy_get_alias(buddy);
	const gchar *group_name = purple_group_get_name(group);
	
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/buddylist/addBuddy";
	gchar *uuid = purple_uuid_random();
	
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append_printf(postdata, "authorizationMsg=%s&", purple_url_encode(message));
	g_string_append_printf(postdata, "buddy=%s&", purple_url_encode(who));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "group=%s&", purple_url_encode(group_name));
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "nick=%s&", purple_url_encode(alias && *alias ? alias : who));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append(postdata, "preAuthorized=true&");
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}

#if !PURPLE_VERSION_CHECK(3, 0, 0)
static void
icq_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	icq_add_buddy_with_invite(pc, buddy, group, NULL);
}
#endif

static void
icq_remove_buddy_by_name(IcyQueAccount *ia, const gchar *who)
{
	GString *postdata = g_string_new(NULL);
	const gchar *url = ICQ_API_SERVER "/buddylist/removeBuddy";
	gchar *uuid = purple_uuid_random();
	
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "allGroups=true&");
	g_string_append_printf(postdata, "buddy=%s&", purple_url_encode(who));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}

// static void
// icq_remove_buddy(PurpleConnection *connection, PurpleBuddy *buddy, PurpleGroup *group)
// {
	// IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	// const gchar *buddy_name = purple_buddy_get_name(buddy);
	
	// icq_remove_buddy_by_name(ia, buddy_name);
// }

static void 
icq_chat_leave(PurpleConnection *pc, int id)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *sn;
	PurpleChatConversation *chatconv;
	
	chatconv = purple_conversations_find_chat(pc, id);
	sn = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "sn");
	if (sn == NULL) {
		sn = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_if_fail(sn);
	}
	
	return icq_remove_buddy_by_name(ia, sn);
}

static void
icq_chat_kick(PurpleConnection *pc, int id, const gchar *who)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *sn;
	PurpleChatConversation *chatconv;
	
	chatconv = purple_conversations_find_chat(pc, id);
	sn = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "sn");
	if (sn == NULL) {
		sn = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_if_fail(sn);
	}
	
	GString *postdata = g_string_new(NULL);
	gchar *uuid = purple_uuid_random();
	const gchar *url = ICQ_API_SERVER "/mchat/DelMembers";
	
	// Needs to be alphabetical
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append_printf(postdata, "chat_id=%s&", purple_url_encode(sn));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "members=%s&", purple_url_encode(who));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}

static GList *
icq_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Group ID");
	pce->identifier = "sn";
	pce->required = TRUE;
	m = g_list_append(m, pce);
	
	return m;
}

static GHashTable *
icq_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	
	if (chatname != NULL)
	{
		g_hash_table_insert(defaults, "sn", g_strdup(chatname));
	}
	
	return defaults;
}

static gchar *
icq_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL)
		return NULL;
	
	temp = g_hash_table_lookup(data, "sn");

	if (temp == NULL)
		return NULL;

	return g_strdup(temp);
}

static void
icq_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	GString *postdata = g_string_new(NULL);
	gchar *uuid = purple_uuid_random();
	const gchar *url = ICQ_API_SERVER "/mchat/AddChat";
	PurpleChatConversation *chatconv = purple_conversations_find_chat(pc, id);
	const gchar *sn = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "sn");
	
	if (!sn) {
		sn = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_if_fail(sn);
	}
	
	// Needs to be alphabetical
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append_printf(postdata, "chat_id=%s&", purple_url_encode(sn));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "members=%s&", purple_url_encode(who));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
}


static void
icq_join_chat_got_chat_info_cb(IcyQueAccount *ia, JsonObject *data, gpointer user_data){
	// Example response:
	/*
		{
			"ts": 1576097893,
			"status": {
				"code": 20000
			},
			"method": "getIdInfo",
			"reqId": "censored",
			"results": {
				"chat": {
					"sn": "682293892@chat.agent",
					"about": "Just learning",
					"name": "Test",
					"stamp": "AoLFq-UEyLqpbUxAA0c",
					"memberCount": 2,
					"public": true
				}
			}
		}
	*/

	JsonObject *json_results = json_object_get_object_member(data, "results");
	JsonObject *json_chat = json_object_get_object_member(json_results, "chat");

	const gchar *chat_sn = json_object_get_string_member(json_chat, "sn");
	const gchar *chat_name = json_object_get_string_member(json_chat, "name");
	const gchar *chat_stamp = json_object_get_string_member(json_chat, "stamp");
	const gchar *chat_about = json_object_get_string_member(json_chat, "about");
	

	PurpleChatConversation *chatconv = purple_serv_got_joined_chat(ia->pc, g_str_hash(chat_sn), chat_sn);
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "sn", g_strdup(chat_sn));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "stamp", g_strdup(chat_stamp));
	purple_conversation_set_title(PURPLE_CONVERSATION(chatconv), g_strdup(chat_name));
	purple_conv_chat_set_topic(chatconv, NULL, g_strdup(chat_about));

	//TODO download history and room list members
}

static void
icq_joined_chat_cb(IcyQueAccount *ia, JsonObject *data, gpointer user_data){
	gchar *chatId = user_data;

	// {"method":"getIdInfo","reqId":"censored","aimsid":"censored","params":{"id":"AoLFq-UEyLqpbUxAA0c"}}
	JsonObject* getIdInfoParams = json_object_new();
	json_object_set_string_member(getIdInfoParams, "aimsid", ia->aimsid);
	json_object_set_string_member(getIdInfoParams, "id", chatId);

	JsonObject* getIdInfoRequest = icq_generate_robusto_request(ia, "getIdInfo", getIdInfoParams);

	gchar* getIdInfoRequestStr = json_object_to_string(getIdInfoRequest);
	json_object_unref(getIdInfoRequest);
	g_free(chatId);
	
	icq_fetch_url_with_method(ia, "POST", ICQ_RAPI_SERVER, getIdInfoRequestStr, icq_join_chat_got_chat_info_cb, NULL);
	g_free(getIdInfoRequestStr);
}

static int
icq_join_chat_send_request(IcyQueAccount *ia, const gchar *chatId)
{
	// {"method":"joinChat","reqId":"censored","aimsid":"censored","params":{"stamp":"AoLFq-UEyLqpbUxAA0c"}}
	JsonObject* joinChatParams = json_object_new();
	json_object_set_string_member(joinChatParams, "aimsid", ia->aimsid);
	json_object_set_string_member(joinChatParams, "stamp", chatId);

	JsonObject *joinChatRequest = icq_generate_robusto_request(ia, "joinChat", joinChatParams);

	gchar* joinChatRequestStr = json_object_to_string(joinChatRequest);
	json_object_unref(joinChatRequest);
	
	icq_fetch_url_with_method(ia, "POST", ICQ_RAPI_SERVER, joinChatRequestStr, icq_joined_chat_cb, g_strdup(chatId));
	g_free(joinChatRequestStr);
}	

static void
icq_join_chat(PurpleConnection *pc, GHashTable *data)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *sn;
	PurpleChatConversation *chatconv;
	
	sn = g_hash_table_lookup(data, "sn");
	if (sn == NULL)
	{
		return;
	}
	
	chatconv = purple_conversations_find_chat_with_account(sn, ia->account);
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}

	icq_join_chat_send_request(ia, sn);

}

static void
icq_sent_msg(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *response = json_object_get_object_member(obj, "response");
	JsonObject *data = json_object_get_object_member(response, "data");
	const gchar *msgId = json_object_get_string_member(data, "msgId");
	
	if (msgId != NULL) {
		gchar *id = g_strdup(msgId);
		g_hash_table_replace(ia->sent_messages_hash, id, id);
	}
	
}

static int
icq_send_msg(IcyQueAccount *ia, const gchar *to, const gchar *message)
{
	GString *postdata = g_string_new(NULL);
	gchar *stripped = purple_markup_strip_html(message);
	gchar *uuid = purple_uuid_random();
	const gchar *url = ICQ_API_SERVER "/im/sendIM";
	
	// Needs to be alphabetical
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append(postdata, "mentions=&");
	g_string_append_printf(postdata, "message=%s&", purple_url_encode(stripped));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append(postdata, "offlineIM=true&");
	g_string_append_printf(postdata, "t=%s&", purple_url_encode(to));
	g_string_append_printf(postdata, "ts=%d", (int) time(NULL));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, icq_sent_msg, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(stripped);
	g_free(uuid);
	
	return 1;
}	

static int
icq_send_im(PurpleConnection *pc,
#if PURPLE_VERSION_CHECK(3, 0, 0)
				PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
				const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	
	return icq_send_msg(ia, who, message);
}

static gint
icq_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(pc, id);
	const gchar *sn = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "sn");
	
	if (!sn) {
		sn = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_val_if_fail(sn, -1);
	}
	
	return icq_send_msg(ia, sn, message);
}

static guint
icq_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);
	GString *postdata = g_string_new(NULL);
	gchar *uuid = purple_uuid_random();
	const gchar *url = ICQ_API_SERVER "/im/setTyping";
	const gchar *typingStatus = "typing";
	
	if (state == PURPLE_IM_TYPED) {
		typingStatus = "typed";
	} else if (state == PURPLE_IM_NOT_TYPING) {
		typingStatus = "none";
	}
	
	// Needs to be alphabetical
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "aimsid=%s&", purple_url_encode(ia->aimsid));
	g_string_append(postdata, "f=json&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "nonce=%s&", purple_url_encode(uuid));
	g_string_append_printf(postdata, "t=%s&", purple_url_encode(who));
	g_string_append_printf(postdata, "ts=%d&", (int) time(NULL));
	g_string_append_printf(postdata, "typingStatus=%s", typingStatus);
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, NULL /*TODO*/, NULL);
	
	g_string_free(postdata, TRUE);
	g_free(uuid);
	
	return 10;
}

static void
icq_got_buddy_icon(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	PurpleBuddy *buddy = user_data;

	if (obj != NULL) {
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;
		const gchar *buddyIcon = g_dataset_get_data(buddy, "buddyIcon");

		response_str = g_dataset_get_data(obj, "raw_body");
		response_len = json_object_get_int_member(obj, "len");
		response_dup = g_memdup(response_str, response_len);

		const gchar *username = purple_buddy_get_name(buddy);
		
		purple_buddy_icons_set_for_user(ia->account, username, response_dup, response_len, buddyIcon);
	}
	
	g_dataset_destroy(buddy);
}

static void
icq_get_chat_history(IcyQueAccount *ia, const gchar* chatId, const gchar* fromMsg, gint64 count, IcyQueProxyCallbackFunc callback, gpointer user_data)
{
	JsonObject* getHistoryParams = json_object_new();
	json_object_set_string_member(getHistoryParams, "aimsid", ia->aimsid);
	json_object_set_string_member(getHistoryParams, "lang", "en-US");
	//FIXME: I have absolutely no idea where this comes from or what this is.
	//TODO: the initial histDlgState event contains a patchVersion. Store this per conversation and use that..?
	json_object_set_string_member(getHistoryParams, "patchVersion", "1");
	json_object_set_string_member(getHistoryParams, "sn", chatId);
	json_object_set_string_member(getHistoryParams, "fromMsgId", fromMsg);
	json_object_set_int_member(getHistoryParams, "count", count);
	
	JsonObject *getHistoryRequest = icq_generate_robusto_request(ia, "getHistory", getHistoryParams);
	gchar* getHistoryRequestStr = json_object_to_string(getHistoryRequest);
	json_object_unref(getHistoryRequest);
	
	icq_fetch_url_with_method(ia, "POST", ICQ_RAPI_SERVER, getHistoryRequestStr, callback, user_data);
	g_free(getHistoryRequestStr);
}

static GList *valid_icyque_accounts = NULL;
#define ICYQUE_ACCOUNT_IS_VALID(ia) (g_list_find(valid_icyque_accounts, (ia)) != NULL)

static void
icq_mark_message_as_read(IcyQueAccount *ia, const gchar *sn, const gchar *messageId)
{
	JsonObject *setDlgStateParams = json_object_new();
	JsonArray *exclude = json_array_new();
	json_object_set_string_member(setDlgStateParams, "aimSid", ia->aimsid);
	json_object_set_array_member(setDlgStateParams, "exclude", exclude);
	json_object_set_string_member(setDlgStateParams, "lastRead", messageId);
	json_object_set_string_member(setDlgStateParams, "sn", sn);
	
	JsonObject *setDlgStateRequest = icq_generate_robusto_request(ia, "setDlgState", setDlgStateParams);
	gchar* setDlgStateRequestStr = json_object_to_string(setDlgStateRequest);
	json_object_unref(setDlgStateRequest);
	
	icq_fetch_url_with_method(ia, "POST", ICQ_RAPI_SERVER, setDlgStateRequestStr, NULL, NULL);
	g_free(setDlgStateRequestStr);
}

static void
icq_unread_message_load_cb(IcyQueAccount *ia, JsonObject *data, gpointer user_data)
{
	JsonObject *status = json_object_get_object_member(data, "status");
	if(status && json_object_get_int_member(status, "code") == 20000) {
		JsonObject *results = json_object_get_object_member(data, "results");
		// Acquire persons first
		JsonArray *persons = json_object_get_array_member(results, "persons");
		const gchar* sn = NULL; // TODO: Support group chats here
		gint i, len = json_array_get_length(persons);
		if(len == 0) return;
		if(len > 1) {
			return;
		}
		JsonObject* firstPerson = json_array_get_object_element(persons, 0);
		sn = json_object_get_string_member(firstPerson, "sn");
	
		JsonArray *messages = json_object_get_array_member(results, "messages");
		len = json_array_get_length(messages);
	
		for (i = (len - 1); i >= 0; i--) {
			JsonObject *message = json_array_get_object_element(messages, i);
			gint64 time = json_object_get_int_member(message, "time");
			const gchar* text = json_object_get_string_member(message, "text");
			gchar *escaped_text = purple_markup_escape_text(text, -1);
			purple_serv_got_im(ia->pc, sn, escaped_text, PURPLE_MESSAGE_RECV, (time_t) time);
			g_free(escaped_text);
		}
		
		// Take the last received message's id, and mark it as read.
		if(len > 0) {
			JsonObject* lastMessage = json_array_get_object_element(messages, 0);
			const gchar* messageId = json_object_get_string_member(lastMessage, "msgId");
			gint64 time = json_object_get_int_member(lastMessage, "time");
			
			ia->last_message_timestamp = MAX(ia->last_message_timestamp, time);
			purple_account_set_int(ia->account, "last_message_timestamp_high", ia->last_message_timestamp >> 32);
			purple_account_set_int(ia->account, "last_message_timestamp_low", ia->last_message_timestamp & 0xFFFFFFFF);
			//TODO: Should this be done directly after retrieiving them here?
			// should it rather be done, when the conversation window is activated?
			// .. Should it be done at all? (Responding to a message automatically marks received messages as read)
			//TODO: Whatever the decision: This should be applied to normal messages (online messages) as well.
			icq_mark_message_as_read(ia, sn, messageId);
		}
	} else {
		purple_debug_warning("icyque", "Failed to retrieve unread messages.");
	}
}

static void
icq_process_event(IcyQueAccount *ia, const gchar *event_type, JsonObject *data)
{
	if (event_type == NULL) return;
	if (!ICYQUE_ACCOUNT_IS_VALID(ia)) return;
	
	if (purple_strequal(event_type, "presence")) {
		const gchar *aimId = json_object_get_string_member(data, "aimId");
		const gchar *state = json_object_get_string_member(data, "state");
		const gchar *statusMsg = json_object_get_string_member(data, "statusMsg");
		
		if (statusMsg != NULL) {
			purple_protocol_got_user_status(ia->account, aimId, state, "message", statusMsg, NULL);
		} else {
			purple_protocol_got_user_status(ia->account, aimId, state, NULL);
		}
		
		PurpleBuddy *pbuddy = purple_blist_find_buddy(ia->account, aimId);
		if (pbuddy != NULL) {
			const gchar *buddyIcon = json_object_get_string_member(data, "buddyIcon");
			
			if (!purple_strequal(purple_buddy_icons_get_checksum_for_user(pbuddy), buddyIcon)) {
				g_dataset_set_data_full(pbuddy, "buddyIcon", g_strdup(buddyIcon), g_free);
				
				icq_fetch_url_with_method(ia, "GET", buddyIcon, NULL, icq_got_buddy_icon, pbuddy);
			}
		}
		
	} else if (purple_strequal(event_type, "typing")) {
		const gchar *aimId = json_object_get_string_member(data, "aimId");
		const gchar *typingStatus = json_object_get_string_member(data, "typingStatus");
		PurpleIMTypingState typing_state;
		
		if (purple_strequal(typingStatus, "typing")) {
			typing_state = PURPLE_IM_TYPING;
		} else if (purple_strequal(typingStatus, "typed")) {
			typing_state = PURPLE_IM_TYPED;
		} else {
			typing_state = PURPLE_IM_NOT_TYPING;
		}
		
		purple_serv_got_typing(ia->pc, aimId, 10, typing_state);
		
	} else if (purple_strequal(event_type, "histDlgState")) {
		const gchar *sn = json_object_get_string_member(data, "sn");
		// Use initial fetch-event (starting == true) to load all unread messages.
		if(json_object_get_boolean_member(data, "starting")) {
			guint64 unreadMsgCnt = json_object_get_int_member(data, "unreadCnt");
			if(unreadMsgCnt > 0) {
				purple_debug_info("icyque", "Acquiring unread messages for conversation: %s\n", sn);
				//TODO: "fromMsgId == -1" means last message. So the following loads all messages that are unread.
				// Should we instead store the last message id that we saw, and sync all messages that have been sent
				// in the meantime (with other clients e.g.) ?
				//FIXME: Do NOT use "-1" here. This might lead to a race condition, when another client sends a new message now.
				icq_get_chat_history(ia, sn, "-1", -unreadMsgCnt, icq_unread_message_load_cb, NULL);
			}
		} else {
			JsonObject *tail = json_object_get_object_member(data, "tail");
			JsonArray *messages = json_object_get_array_member((tail != NULL ? tail : data), "messages");
			guint i, len = json_array_get_length(messages);
			
			for (i = 0; i < len; i++) {
				JsonObject *message = json_array_get_object_element(messages, i);
				gint64 time = json_object_get_int_member(message, "time");
				
				if (ia->last_message_timestamp && time > ia->last_message_timestamp) {
					const gchar *mediaType = json_object_get_string_member(message, "mediaType");
					const gchar *text = json_object_get_string_member(message, "text");
					PurpleMessageFlags msg_flags = PURPLE_MESSAGE_RECV;
					
					if (json_object_get_boolean_member(message, "outgoing")) {
						msg_flags = PURPLE_MESSAGE_SEND;
						
						const gchar *wid = json_object_get_string_member(message, "wid");
						if (wid && g_hash_table_remove(ia->sent_messages_hash, wid)) {
							// We sent this message from Pidgin
							continue;
						}
					}
					
					gchar *escaped_text = purple_markup_escape_text(text, -1);
					
					if (g_str_has_suffix(sn, "@chat.agent")) {
						// Group chat
						JsonObject *chat = json_object_get_object_member(message, "chat");
						const gchar *sender = json_object_get_string_member(chat, "sender");
						const gchar *chatName = json_object_get_string_member(chat, "name");
						JsonObject *memberEvent = json_object_get_object_member(chat, "memberEvent");
						
						if (memberEvent != NULL) {
							PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(sn, ia->account);
							const gchar *memberEventType = json_object_get_string_member(memberEvent, "type");
							if (purple_strequal(memberEventType, "invite") || purple_strequal(memberEventType, "addMembers")) {
								JsonArray *members = json_object_get_array_member(memberEvent, "members");
								//add members to the group chat
								const gchar *role = json_object_get_string_member(memberEvent, "role");
								PurpleChatUserFlags cbflags = PURPLE_CHAT_USER_NONE;
								if (purple_strequal(role, "admin")) {
									cbflags = PURPLE_CHAT_USER_OP;
								} else if (purple_strequal(role, "moder")) {
									cbflags = PURPLE_CHAT_USER_HALFOP;
								}
								
								GList *users = NULL, *flags = NULL;
								int j;
								for (j = json_array_get_length(members) - 1; j >= 0; j--) {
									const gchar *member = json_array_get_string_element(members, j);
									
									users = g_list_prepend(users, g_strdup(member));
									flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
								}
								
								purple_chat_conversation_add_users(chatconv, users, NULL, flags, TRUE);
								while (users != NULL) {
									g_free(users->data);
									users = g_list_delete_link(users, users);
								}
								g_list_free(flags);
								
							} else if (purple_strequal(memberEventType, "delMembers")) {
								JsonArray *members = json_object_get_array_member(memberEvent, "members");
								//remove members from the group chat
								GList *users = NULL;
								int j;
								for (j = json_array_get_length(members) - 1; j >= 0; j--) {
									const gchar *member = json_array_get_string_element(members, j);
									
									users = g_list_prepend(users, g_strdup(member));
								}
								
								purple_chat_conversation_remove_users(chatconv, users, NULL);
								while (users != NULL) {
									g_free(users->data);
									users = g_list_delete_link(users, users);
								}
							}
							
							
						} else if (purple_strequal(mediaType, "text")) {
							PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(sn, ia->account);
							if (chatconv == NULL) {
								chatconv = purple_serv_got_joined_chat(ia->pc, g_str_hash(sn), sn);
								purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "sn", g_strdup(sn));
								purple_chat_conversation_set_topic(chatconv, NULL, chatName);
							}
							
							purple_serv_got_chat_in(ia->pc, g_str_hash(sn), sender, msg_flags, escaped_text, time);
							
						} else {
							purple_debug_warning("icyque", "Unknown chat message mediaType '%s'\n", mediaType);
						}
						
					} else {
						// One-to-one IM
						if (purple_strequal(mediaType, "text")) {
								if (msg_flags & PURPLE_MESSAGE_SEND) {
									PurpleIMConversation *imconv = purple_conversations_find_im_with_account(sn, ia->account);
									PurpleMessage *msgObj = purple_message_new_outgoing(sn, escaped_text, msg_flags);
									if (imconv == NULL)
									{
										imconv = purple_im_conversation_new(ia->account, sn);
									}
									purple_message_set_time(msgObj, time);
									purple_conversation_write_message(PURPLE_CONVERSATION(imconv), msgObj);
									
								} else {
									purple_serv_got_im(ia->pc, sn, escaped_text, msg_flags, (time_t) time);
								}
						} else {
							purple_debug_warning("icyque", "Unknown IM message mediaType '%s'\n", mediaType);
						}
					}
					
					g_free(escaped_text);
				}
				
				ia->last_message_timestamp = MAX(ia->last_message_timestamp, time);
				purple_account_set_int(ia->account, "last_message_timestamp_high", ia->last_message_timestamp >> 32);
				purple_account_set_int(ia->account, "last_message_timestamp_low", ia->last_message_timestamp & 0xFFFFFFFF);
			}
		}
	} else if (purple_strequal(event_type, "userAddedToBuddyList")) {
		/*{
					"requester": "123456789",
					"displayAIMid": "Person Name",
					"authRequested": 0
				}, */
				
	} else if (purple_strequal(event_type, "buddylist")) {
		JsonArray *groups = json_object_get_array_member(data, "groups");
		guint i, len = json_array_get_length(groups);
		
		for (i = 0; i < len; i++) {
			JsonObject *group = json_array_get_object_element(groups, i);
			const gchar *group_name = json_object_get_string_member(group, "name");
			PurpleGroup *pgroup = icq_get_or_create_default_group(group_name);
			JsonArray *buddies = json_object_get_array_member(group, "buddies");
			guint j, buddies_len = json_array_get_length(buddies);
			
			for (j = 0; j < buddies_len; j++) {
				JsonObject *buddy = json_array_get_object_element(buddies, j);
				const gchar *aimId = json_object_get_string_member(buddy, "aimId");
				const gchar *state = json_object_get_string_member(buddy, "state");
				const gchar *statusMsg = json_object_get_string_member(buddy, "statusMsg");
				
				if (g_str_has_suffix(aimId, "@chat.agent")) {
					// Group chat
					PurpleChat *chat = purple_blist_find_chat(ia->account, aimId);
					
					if (chat == NULL) {
						const gchar *friendly = json_object_get_string_member(buddy, "friendly");
						chat = purple_chat_new(ia->account, friendly, icq_chat_info_defaults(ia->pc, aimId));
						
						purple_blist_add_chat(chat, pgroup, NULL);
					}
					
				} else {
					// Buddy
					PurpleBuddy *pbuddy = purple_blist_find_buddy(ia->account, aimId);
					
					if (pbuddy == NULL) {
						const gchar *friendly = json_object_get_string_member(buddy, "friendly");
						pbuddy = purple_buddy_new(ia->account, aimId, friendly);
						
						purple_blist_add_buddy(pbuddy, NULL, pgroup, NULL);
					}
					
					if (statusMsg != NULL) {
						purple_protocol_got_user_status(ia->account, aimId, state, "message", statusMsg, NULL);
					} else {
						purple_protocol_got_user_status(ia->account, aimId, state, NULL);
					}
				}
			}
		}
		
	}
}

static void
icq_fetch_events_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	if (!ICYQUE_ACCOUNT_IS_VALID(ia)) return;
	
	if (obj == NULL) {
		icq_fetch_url_with_method(ia, "GET", ia->last_fetchBaseURL, NULL, icq_fetch_events_cb, NULL);
		return;
	}
	
	JsonObject *response = json_object_get_object_member(obj, "response");
	JsonObject *data = json_object_get_object_member(response, "data");
	
	const gchar *fetchBaseURL = json_object_get_string_member(data, "fetchBaseURL");
	JsonArray *events = json_object_get_array_member(data, "events");
	guint i, len = json_array_get_length(events);
	for (i = 0; i < len; i++) {
		JsonObject *event = json_array_get_object_element(events, i);
		const gchar *type = json_object_get_string_member(event, "type");
		JsonObject *eventData = json_object_get_object_member(event, "eventData");
		
		icq_process_event(ia, type, eventData);
	}
	
	g_free(ia->last_fetchBaseURL);
	ia->last_fetchBaseURL = g_strdup(fetchBaseURL);
	
	icq_fetch_url_with_method(ia, "GET", fetchBaseURL, NULL, icq_fetch_events_cb, NULL);
}

static void
icq_robusto_add_client_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *status = json_object_get_object_member(obj, "status");
	if(!status || json_object_get_int_member(status, "code") != 20000) {
		purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Failed to register client at robusto API.");
	} else {
		JsonObject *results = json_object_get_object_member(obj, "results");
		guint64 clientId = json_object_get_int_member(results, "clientId");
		ia->robusto_client_id = clientId;
		
		purple_connection_set_state(ia->pc, PURPLE_CONNECTION_CONNECTED);
		purple_debug_info("icyque", "Authentication succeeded. Starting fetch-loop.\n");
		icq_fetch_url_with_method(ia, "GET", ia->last_fetchBaseURL, NULL, icq_fetch_events_cb, NULL);
	}
}

static void icq_robusto_add_client(IcyQueAccount *ia)
{
	JsonObject *addClientParams = json_object_new();
	JsonObject *addClientParamsUserAgent = json_object_new();
	json_object_set_object_member(addClientParams, "ua", addClientParamsUserAgent);
	json_object_set_string_member(addClientParamsUserAgent, "app", "icq"); //TODO pretend to be official client or Pidgin?
	json_object_set_string_member(addClientParamsUserAgent, "build", "1");
	json_object_set_string_member(addClientParamsUserAgent, "label", "webicq");
	json_object_set_string_member(addClientParamsUserAgent, "os", "win");
	json_object_set_string_member(addClientParamsUserAgent, "version", "0.1");
	
	JsonObject *addClientRequest = icq_generate_robusto_request(ia, "addClient", addClientParams);

	const gchar* addClientRequestStr = json_object_to_string(addClientRequest);
	json_object_unref(addClientRequest);
	
	purple_debug_info("icyque", "Registering client at ICQ RAPI.\n");
	icq_fetch_url_with_method(ia, "POST", ICQ_RAPI_SERVER, addClientRequestStr, icq_robusto_add_client_cb, NULL);
}

static void
icq_robusto_gen_token_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *results = json_object_get_object_member(obj, "results");
	const gchar *authToken = json_object_get_string_member(results, "authToken");
	
	if(authToken == NULL) {
		purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Failed to acquire authentication token (robusto).");
	} else {
		ia->robusto_token = g_strdup(authToken);
		icq_robusto_add_client(ia);
	}
}

static void icq_robusto_gen_token(IcyQueAccount *ia)
{
	const gchar *url = ICQ_RAPI_SERVER "/genToken";
	GString *postdata = g_string_new(NULL);
	
	// Make sure these are added alphabetically for the signature to work
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append_printf(postdata, "ts=%d", (int)(time(NULL) - ia->server_time_offset));
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, icq_robusto_gen_token_cb, NULL);
	g_string_free(postdata, TRUE);
}

static void
icq_session_start_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	if (!ICYQUE_ACCOUNT_IS_VALID(ia)) return;
	
	JsonObject *response = json_object_get_object_member(obj, "response");
	JsonObject *data = json_object_get_object_member(response, "data");
	
	const gchar *aimsid = json_object_get_string_member(data, "aimsid");
	const gchar *fetchBaseURL = json_object_get_string_member(data, "fetchBaseURL");
	
	ia->aimsid = g_strdup(aimsid);
	ia->last_fetchBaseURL = g_strdup(fetchBaseURL);
	
	icq_robusto_gen_token(ia);
}

static void
icq_session_start(IcyQueAccount *ia)
{
	if (!ICYQUE_ACCOUNT_IS_VALID(ia)) return;
	
	const gchar *url = ICQ_API_SERVER "/aim/startSession";
	GString *postdata = g_string_new(NULL);
	
	// Make sure these are added alphabetically for the signature to work
	g_string_append_printf(postdata, "a=%s&", purple_url_encode(ia->token));
	// g_string_append_printf(postdata, "assertCaps=%s&", purple_url_encode(ICQ_ASSERT_CAPS));
	// g_string_append_printf(postdata, "buildNumber=%s&", purple_url_encode("23341"));
	// g_string_append_printf(postdata, "clientName=%s&", purple_url_encode("ICQ"));
	g_string_append_printf(postdata, "deviceId=%s&", purple_url_encode(ia->device_id));
	g_string_append_printf(postdata, "events=%s&", purple_url_encode(ICQ_EVENTS));
	g_string_append(postdata, "f=json&");
	g_string_append(postdata, "imf=plain&");
	g_string_append_printf(postdata, "includePresenceFields=%s&", purple_url_encode(ICQ_PRESENCE_FIELDS));
	// g_string_append_printf(postdata, "interestCaps=%s&", purple_url_encode("094613504C7F11D18222444553540000,094613514C7F11D18222444553540000,8EEC67CE70D041009409A7C1602A5C84"));
	g_string_append(postdata, "invisible=false&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append(postdata, "language=en-US&");
	g_string_append(postdata, "rawMsg=0&");
	g_string_append(postdata, "sessionTimeout=31536000&");
	//g_string_append(postdata, "sig_sha256_force=1&");
	g_string_append_printf(postdata, "ts=%d&", (int)(time(NULL) - ia->server_time_offset));
	g_string_append(postdata, "view=online"); //todo mobile?
	
	gchar *sig_sha256 = icq_get_url_sign(ia, TRUE, url, postdata->str);
	g_string_append_printf(postdata, "&sig_sha256=%s", purple_url_encode(sig_sha256));
	g_free(sig_sha256);
	
	icq_fetch_url_with_method(ia, "POST", url, postdata->str, icq_session_start_cb, NULL);
	
	g_string_free(postdata, TRUE);
}

static void
icq_login_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *response = json_object_get_object_member(obj, "response");
	
	if (json_object_get_int_member(response, "statusCode") == 200) {
		JsonObject *data = json_object_get_object_member(response, "data");
		JsonObject *token = json_object_get_object_member(data, "token");
		const gchar *a = json_object_get_string_member(token, "a");
		const gchar *loginId = json_object_get_string_member(data, "loginId");
		const gchar *sessionSecret = json_object_get_string_member(data, "sessionSecret");
		const gint64 hostTime = json_object_get_int_member(data, "hostTime");
		
		if (a != NULL) {
			ia->token = g_strdup(purple_url_decode(a));
			ia->session_key = icq_generate_signature(sessionSecret, purple_connection_get_password(ia->pc));
			ia->server_time_offset = (gint64)time(NULL) - hostTime;
			purple_connection_set_display_name(ia->pc, loginId);
			
			purple_account_set_string(ia->account, "token", ia->token);
			purple_account_set_string(ia->account, "session_key", ia->session_key);
			purple_account_set_int(ia->account, "server_time_offset", ia->server_time_offset);
			
			icq_session_start(ia);
			
			return;
		}
	}
	
	purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Bad username/password"));
}

static void
icq_mfa_text_entry_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *response = json_object_get_object_member(obj, "response");
	
	if (json_object_get_int_member(response, "statusCode") == 200) {
		JsonObject *data = json_object_get_object_member(response, "data");
		JsonObject *token = json_object_get_object_member(data, "token");
		const gchar *a = json_object_get_string_member(token, "a");
		const gchar *loginId = json_object_get_string_member(data, "loginId");
		const gchar *sessionKey = json_object_get_string_member(data, "sessionKey");
		
		if (a != NULL) {
			ia->token = g_strdup(purple_url_decode(a));
			ia->session_key = g_strdup(sessionKey);
			purple_connection_set_display_name(ia->pc, loginId);
			
			purple_account_set_string(ia->account, "token", ia->token);
			purple_account_set_string(ia->account, "session_key", ia->session_key);
			
			icq_session_start(ia);
			
			return;
		}
	}
	
	purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Bad username/password"));
}

static void
icq_mfa_text_entry(gpointer user_data, const gchar *code)
{
	IcyQueAccount *ia = user_data;
	const gchar *username = purple_account_get_username(ia->account);
	GString *postdata = g_string_new(NULL);
	
	g_string_append_printf(postdata, "msisdn=%s&", purple_url_encode(&username[1]));
	g_string_append_printf(postdata, "trans_id=%s&", purple_url_encode(ia->sms_trans_id));
	g_string_append_printf(postdata, "sms_code=%s&", purple_url_encode(code));
	g_string_append(postdata, "locale=en&");
	g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
	g_string_append(postdata, "platform=web&");
	g_string_append(postdata, "create_account=1&");
	g_string_append(postdata, "client=icq&");
	g_string_append_printf(postdata, "r=%d&", g_random_int());
	
	icq_fetch_url_with_method(ia, "POST", "https://u.icq.net/smsreg/loginWithPhoneNumber.php", postdata->str, icq_mfa_text_entry_cb, NULL);

	g_string_free(postdata, TRUE);
	
	g_free(ia->sms_trans_id);
	ia->sms_trans_id = NULL;
}

static void
icq_mfa_cancel(gpointer user_data)
{
	IcyQueAccount *ia = user_data;

	purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Cancelled 2FA auth"));
}

static void
icq_sms_login_cb(IcyQueAccount *ia, JsonObject *obj, gpointer user_data)
{
	JsonObject *response = json_object_get_object_member(obj, "response");
	
	if (json_object_get_int_member(response, "statusCode") == 200) {
		JsonObject *data = json_object_get_object_member(response, "data");
		const gchar *trans_id = json_object_get_string_member(data, "trans_id");
		ia->sms_trans_id = g_strdup(trans_id);
		
		purple_request_input(ia->pc, _("Two-factor authentication"),
							 _("Enter SMS code"),
							 _("You will be sent an SMS message containing your auth code."),
							 NULL, FALSE, FALSE, "",
							 _("_Login"), G_CALLBACK(icq_mfa_text_entry),
							 _("_Cancel"), G_CALLBACK(icq_mfa_cancel),
							 purple_request_cpar_from_connection(ia->pc),
							 ia);
	}
}

static void
icq_login(PurpleAccount *account)
{
	IcyQueAccount *ia;
	PurpleConnection *pc = purple_account_get_connection(account);
	
	ia = g_new0(IcyQueAccount, 1);
	purple_connection_set_protocol_data(pc, ia);
	ia->account = account;
	ia->pc = pc;
	ia->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ia->user_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ia->sent_messages_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	ia->device_id = g_strdup(purple_account_get_string(ia->account, "device_id", NULL));
	ia->keepalive_pool = purple_http_keepalive_pool_new();
	ia->token = g_strdup(purple_account_get_string(ia->account, "token", NULL));
	ia->session_key = g_strdup(purple_account_get_string(ia->account, "session_key", NULL));
	ia->server_time_offset = purple_account_get_int(ia->account, "server_time_offset", 0);
	ia->robusto_client_id = -1;
	
	if (ia->device_id == NULL) {
		//TODO pretend to be official client or Pidgin?
		ia->device_id = g_strdup_printf("icq-%08x%08x", g_random_int(), g_random_int());
		purple_account_set_string(ia->account, "device_id", ia->device_id);
	}
	
	ia->last_message_timestamp = purple_account_get_int(account, "last_message_timestamp_high", 0);

	if (ia->last_message_timestamp != 0) {
		ia->last_message_timestamp = (ia->last_message_timestamp << 32) | ((guint64) purple_account_get_int(account, "last_message_timestamp_low", 0) & 0xFFFFFFFF);
	}
	
	valid_icyque_accounts = g_list_append(valid_icyque_accounts, ia);
	
	
	if (ia->token == NULL) {
		const gchar *username = purple_account_get_username(account);
		GString *postdata = g_string_new(NULL);
		
		if (username[0] != '+') {		
			//TODO do we pretend to be an official device?
			g_string_append_printf(postdata, "clientName=%s&", purple_url_encode("ICQ"));
			g_string_append_printf(postdata, "clientVersion=%s&", purple_url_encode("7.4"));
			g_string_append_printf(postdata, "devId=%s&", purple_url_encode(ICQ_DEVID));
			g_string_append(postdata, "f=json&");
			g_string_append(postdata, "idType=ICQ&");
			g_string_append_printf(postdata, "pwd=%s&", purple_url_encode(purple_connection_get_password(pc)));
			g_string_append_printf(postdata, "s=%s&", purple_url_encode(username));
			
			icq_fetch_url_with_method(ia, "POST", "https://api.login.icq.net/auth/clientLogin", postdata->str, icq_login_cb, NULL);
			
		} else {
			// Phone/SMS auth
			g_string_append_printf(postdata, "msisdn=%s&", purple_url_encode(&username[1]));
			g_string_append(postdata, "locale=en&");
			g_string_append(postdata, "countryCode=ru&");
			g_string_append_printf(postdata, "k=%s&", purple_url_encode(ICQ_DEVID));
			g_string_append(postdata, "version=1&");
			g_string_append(postdata, "platform=web&");
			g_string_append(postdata, "client=icq&");
			g_string_append(postdata, "checks=sms&");
			g_string_append_printf(postdata, "r=%d&", g_random_int());
			
			icq_fetch_url_with_method(ia, "POST", "https://u.icq.net/smsreg/requestPhoneValidation.php", postdata->str, icq_sms_login_cb, NULL);
			
		}
		
		g_string_free(postdata, TRUE);
	} else {
		icq_session_start(ia);
	}
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
}


static void
icq_close(PurpleConnection *pc)
{
	IcyQueAccount *ia = purple_connection_get_protocol_data(pc);

	g_return_if_fail(ia != NULL);
	
	if (ia->heartbeat_timeout) {
		g_source_remove(ia->heartbeat_timeout);
	}
	
	valid_icyque_accounts = g_list_remove(valid_icyque_accounts, ia);
	
	while (ia->http_conns) {
		purple_http_conn_cancel(ia->http_conns->data);
		ia->http_conns = g_slist_delete_link(ia->http_conns, ia->http_conns);
	}
	
	purple_http_keepalive_pool_unref(ia->keepalive_pool);

	// Save cookies to accounts.xml to login with later
	gchar *cookies = icq_cookies_to_string(ia);
	purple_account_set_string(ia->account, "cookies", cookies);
	g_free(cookies);
	g_hash_table_destroy(ia->cookie_table);
	ia->cookie_table = NULL;
	g_hash_table_destroy(ia->sent_messages_hash);
	ia->sent_messages_hash = NULL;
	g_hash_table_destroy(ia->user_ids);
	ia->user_ids = NULL;
	
	g_free(ia->last_fetchBaseURL);
	g_free(ia->token);
	g_free(ia->session_key);
	g_free(ia->aimsid);
	g_free(ia->robusto_token);
	g_free(ia->sms_trans_id);
	
	g_free(ia);
}

static PurpleCmdRet
icq_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	icq_chat_leave(pc, id);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
icq_cmd_kick(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	icq_chat_kick(pc, id, args[0]);
	
	return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						"prpl-eionrobb-icyque", icq_cmd_leave,
						_("leave:  Leave the group chat"), NULL);
						
	purple_cmd_register("kick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						"prpl-eionrobb-icyque", icq_cmd_kick,
						_("kick <user>:  Kick a user from the room."), NULL);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)

// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();
	
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();
	
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{	
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);

	info = plugin->info;

	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}

	info->extra_info = prpl_info;
#if PURPLE_MINOR_VERSION >= 5
	prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
#endif
#if PURPLE_MINOR_VERSION >= 8
	prpl_info->add_buddy_with_invite = icq_add_buddy_with_invite;
#endif

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_INVITE_MESSAGE | OPT_PROTO_PASSWORD_OPTIONAL;
	// prpl_info->protocol_options = icyque_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

	// prpl_info->get_account_text_table = icyque_get_account_text_table;
	// prpl_info->list_emblem = icyque_list_emblem;
	prpl_info->status_text = icq_status_text;
	prpl_info->tooltip_text = icq_tooltip_text;
	prpl_info->list_icon = icq_list_icon;
	prpl_info->set_status = icq_set_status;
	// prpl_info->set_idle = icyque_set_idle;
	prpl_info->status_types = icq_status_types;
	prpl_info->chat_info = icq_chat_info;
	prpl_info->chat_info_defaults = icq_chat_info_defaults;
	prpl_info->login = icq_login;
	prpl_info->close = icq_close;
	prpl_info->send_im = icq_send_im;
	prpl_info->send_typing = icq_send_typing;
	prpl_info->join_chat = icq_join_chat;
	prpl_info->get_chat_name = icq_get_chat_name;
	// prpl_info->find_blist_chat = icyque_find_chat;
	prpl_info->chat_invite = icq_chat_invite;
	prpl_info->chat_send = icq_chat_send;
	// prpl_info->set_chat_topic = icyque_chat_set_topic;
	// prpl_info->get_cb_real_name = icyque_get_real_name;
	prpl_info->add_buddy = icq_add_buddy;
	// prpl_info->remove_buddy = icyque_buddy_remove;
	// prpl_info->group_buddy = icyque_fake_group_buddy;
	// prpl_info->rename_group = icyque_fake_group_rename;
	prpl_info->get_info = icq_get_info;
	prpl_info->add_deny = icq_block_user;
	prpl_info->rem_deny = icq_unblock_user;

	// prpl_info->roomlist_get_list = icyque_roomlist_get_list;
	// prpl_info->roomlist_room_serialize = icyque_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	"prpl-eionrobb-icyque",			/* id */
	"ICQ (WIM)",					/* name */
	"0.1",							/* version */
	"",								/* summary */
	"",								/* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	"",								/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	NULL,							/* actions */
	NULL,							/* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(icyque, plugin_init, info);

#else

G_MODULE_EXPORT GType icyque_protocol_get_type(void);
#define ICYQUE_TYPE_PROTOCOL			(icyque_protocol_get_type())
#define ICYQUE_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), ICYQUE_TYPE_PROTOCOL, IcyQueProtocol))
#define ICYQUE_PROTOCOL_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), ICYQUE_TYPE_PROTOCOL, IcyQueProtocolClass))
#define ICYQUE_IS_PROTOCOL(obj)		(G_TYPE_CHECK_INSTANCE_TYPE((obj), ICYQUE_TYPE_PROTOCOL))
#define ICYQUE_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), ICYQUE_TYPE_PROTOCOL))
#define ICYQUE_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), ICYQUE_TYPE_PROTOCOL, IcyQueProtocolClass))

typedef struct _IcyQueProtocol
{
	PurpleProtocol parent;
} IcyQueProtocol;

typedef struct _IcyQueProtocolClass
{
	PurpleProtocolClass parent_class;
} IcyQueProtocolClass;

static void
icyque_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = "prpl-eionrobb-icyque";
	info->name = "ICQ (WIM)";
}

static void
icyque_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = icq_login;
	prpl_info->close = icq_close;
	prpl_info->status_types = icq_status_types;
	prpl_info->list_icon = icq_list_icon;
}

static void
icyque_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->status_text = icq_status_text;
	prpl_info->tooltip_text = icq_tooltip_text;
	//prpl_info->buddy_free = icyque_buddy_free;
 	//prpl_info->offline_message = icyque_offline_message;
}

static void
icyque_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->get_info = icq_get_info;
	prpl_info->set_status = icq_set_status;
	//prpl_info->set_idle = icyque_set_idle;
	prpl_info->add_buddy = icq_add_buddy_with_invite;
}

static void
icyque_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	prpl_info->add_deny = icq_block_user;
	prpl_info->rem_deny = icq_unblock_user;
}

static void 
icyque_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = icq_send_im;
	prpl_info->send_typing = icq_send_typing;
}

static void 
icyque_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = icq_chat_send;
	prpl_info->info = icq_chat_info;
	prpl_info->info_defaults = icq_chat_info_defaults;
	prpl_info->join = icq_join_chat;
	prpl_info->get_name = icq_get_chat_name;
	prpl_info->invite = icq_chat_invite;
	//prpl_info->set_topic = icyque_chat_set_topic;
}

static void 
icyque_protocol_media_iface_init(PurpleProtocolMediaIface *prpl_info)
{
	//prpl_info->get_caps = icyque_get_media_caps;
	//prpl_info->initiate_session = icyque_initiate_media;
}

static void 
icyque_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	//prpl_info->get_list = icyque_roomlist_get_list;
}

static PurpleProtocol *icyque_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	IcyQueProtocol, icyque_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  icyque_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  icyque_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  icyque_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  icyque_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  icyque_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_MEDIA_IFACE,
	                                  icyque_protocol_media_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  icyque_protocol_roomlist_iface_init)
);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	icyque_protocol_register_type(plugin);
	icyque_protocol = purple_protocols_add(ICYQUE_TYPE_PROTOCOL, error);
	if (!icyque_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(icyque_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          "prpl-eionrobb-icyque",
		"name",        "ICQ (WIM)",
		"version",     "0.1",
		"category",    N_("Protocol"),
		"summary",     N_("ICQ-WIM Protocol Plugin."),
		"description", N_("Adds ICQ protocol support to libpurple."),
		"website",     "https://github.com/EionRobb/icyque/",
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(icyque, plugin_query,
		libpurple3_plugin_load, libpurple3_plugin_unload);

#endif	
