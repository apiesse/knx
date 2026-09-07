"""Source-level regression contracts for security-sensitive embedded paths.

The upstream library has no native-host BAU/Platform fixture.  These tests use a
small C++-aware scanner (comments and quoted strings are ignored, braces are
balanced) to bind assertions to exact function bodies.  This deliberately
avoids broad grep checks that could be satisfied by comments or unrelated code.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "knx"


def _code_only(text: str) -> str:
    """Replace comments/string contents while preserving code positions."""
    out = list(text)
    i = 0
    state = "code"
    quote = ""
    while i < len(text):
        if state == "code":
            if text.startswith("//", i):
                out[i] = out[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if text.startswith("/*", i):
                out[i] = out[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if text[i] in ('"', "'"):
                quote = text[i]
                out[i] = " "
                i += 1
                state = "quoted"
                continue
        elif state == "line_comment":
            if text[i] == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block_comment":
            out[i] = " "
            if text.startswith("*/", i):
                out[i + 1] = " "
                i += 1
                state = "code"
        elif state == "quoted":
            out[i] = " "
            if text[i] == "\\" and i + 1 < len(text):
                out[i + 1] = " "
                i += 1
            elif text[i] == quote:
                state = "code"
        i += 1
    return "".join(out)


def _read_code(filename: str) -> str:
    return _code_only((SRC / filename).read_text(encoding="utf-8"))


def _function_body(filename: str, qualified_name: str, occurrence: int = 0) -> str:
    code = _read_code(filename)
    signatures = list(re.finditer(r"\b" + re.escape(qualified_name) + r"\s*\(", code))
    if occurrence >= len(signatures):
        raise AssertionError(
            f"missing occurrence {occurrence} of function {qualified_name} in {filename}"
        )
    signature = signatures[occurrence]

    opening = code.find("{", signature.end())
    if opening < 0:
        raise AssertionError(f"missing body for {qualified_name} in {filename}")

    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1 : index]
    raise AssertionError(f"unbalanced body for {qualified_name} in {filename}")


def _assert_contains(test: unittest.TestCase, body: str, pattern: str, message: str) -> re.Match:
    match = re.search(pattern, body, re.DOTALL)
    test.assertIsNotNone(match, message)
    return match


class RouterInputContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.body = _function_body(
            "router_object.cpp", "RouterObject::functionRouteTableControl"
        )

    def test_null_and_short_service_input_are_rejected_before_dereference(self) -> None:
        guard = _assert_contains(
            self,
            self.body,
            r"if\s*\(\s*data\s*==\s*nullptr\s*\|\|\s*length\s*<\s*2\s*\)"
            r"\s*\{[^{}]*ReturnCodes::DataVoid[^{}]*return\s*;[^{}]*\}",
            "route-table callback must return DataVoid for null/<2-byte input",
        )
        self.assertLess(guard.start(), self.body.find("data[1]"))

    def test_group_service_payload_is_six_bytes_before_address_decode(self) -> None:
        length_check = self.body.find("length < 6")
        first_decode = self.body.find("popWord")
        self.assertGreaterEqual(
            length_check, 0, "group route-table service must require a six-byte payload"
        )
        self.assertLess(length_check, first_decode)
        guarded_region = self.body[length_check:first_decode]
        self.assertIn("ReturnCodes::DataVoid", guarded_region)
        self.assertIn("return;", guarded_region)

    def test_inverted_group_ranges_are_rejected_as_data_void(self) -> None:
        # Each independently decoded start/end pair needs its own rejection.  A
        # future refactor may decode once before the command/state dispatch.
        decoded_pairs = self.body.count("popWord") // 2
        checks = list(
            re.finditer(
                r"if\s*\(\s*startAddress\s*>\s*endAddress\s*\)"
                r"\s*\{[^{}]*ReturnCodes::DataVoid[^{}]*return\s*;[^{}]*\}",
                self.body,
                re.DOTALL,
            )
        )
        self.assertGreater(decoded_pairs, 0, "group ranges must be decoded")
        self.assertGreaterEqual(
            len(checks),
            decoded_pairs,
            "every decoded group-address range must fail closed when start > end",
        )


class ResetCascadeContractTest(unittest.TestCase):
    def test_rf_bau_resets_all_device_tables_before_rf_medium(self) -> None:
        body = _function_body("bau27B0.cpp", "Bau27B0::doMasterReset")
        device_reset = body.find("BauSystemBDevice::doMasterReset")
        rf_reset = body.find("_rfMediumObj.masterReset")
        self.assertGreaterEqual(
            device_reset, 0, "RF BAU must include address/association/group/security reset cascade"
        )
        self.assertGreater(rf_reset, device_reset, "RF medium reset must follow the common device reset")

    def test_rf_medium_has_a_factory_reset_override(self) -> None:
        header = _read_code("rf_medium_object.h")
        _assert_contains(
            self,
            header,
            r"void\s+masterReset\s*\(\s*EraseCode\s+\w+\s*,\s*uint8_t\s+\w+\s*\)\s*override\s*;",
            "RfMediumObject must override the InterfaceObject no-op reset",
        )

        body = _function_body("rf_medium_object.cpp", "RfMediumObject::masterReset")
        self.assertIn("EraseCode::FactoryReset", body)
        self.assertIn("EraseCode::FactoryResetWithoutIA", body)
        _assert_contains(
            self,
            body,
            r"PID_RF_MULTI_TYPE[^;]*write\s*\([^;]*0",
            "factory reset must clear the writable RF multi-type property",
        )
        _assert_contains(
            self,
            body,
            r"(?:0xFF\s*,\s*){5}0xFF",
            "factory reset must restore the six-byte RF domain address to FF",
        )
        self.assertRegex(
            body,
            r"(?:rfDomainAddress\s*\(|PID_RF_DOMAIN_ADDRESS\s*\)[^;]*write\s*\()",
        )


class ManagementCallbackContractTest(unittest.TestCase):
    def test_standard_function_command_denies_before_any_callback(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::functionPropertyCommandIndication"
        )
        gate = _assert_contains(
            self,
            body,
            r"if\s*\(\s*!managementWriteAllowed\s*\(\s*\)\s*\)"
            r"\s*\{[^{}]*ReturnCodes::AccessDenied[^{}]*return\s*;[^{}]*\}",
            "standard function-property command needs an early fail-closed gate",
        )
        callback = min(
            position
            for position in (body.find("obj->command"), body.find("_functionProperty("))
            if position >= 0
        )
        self.assertLess(gate.start(), callback)
        self.assertIn("propertyCommandAllowed(prop)", body)
        self.assertRegex(body, r"prop\s*==\s*nullptr\s*&&\s*_functionProperty\s*!=\s*0")

    def test_extended_function_command_denies_before_object_dispatch(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::functionPropertyExtCommandIndication"
        )
        gate = _assert_contains(
            self,
            body,
            r"if\s*\(\s*!managementWriteAllowed\s*\(\s*\)\s*\)"
            r"\s*\{[^{}]*ReturnCodes::AccessDenied[^{}]*return\s*;[^{}]*\}",
            "extended function-property command needs an early fail-closed gate",
        )
        self.assertLess(gate.start(), body.find("getInterfaceObject"))
        self.assertIn("propertyCommandAllowed(prop)", body)

    def test_virtual_state_callback_cannot_bypass_management_window(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::functionPropertyStateIndication"
        )
        guarded_callback = re.compile(
            r"prop\s*==\s*nullptr\s*&&\s*managementWriteAllowed\s*\(\s*\)"
            r"\s*&&\s*_functionPropertyState\s*!=\s*0"
        )
        self.assertGreaterEqual(
            len(guarded_callback.findall(body)),
            1,
            "unknown-PID state fallback must require the management window",
        )
        self.assertRegex(
            body,
            r"if\s*\(\s*managementWriteAllowed\s*\(\s*\)\s*&&\s*"
            r"_functionPropertyState\s*!=\s*0\s*\)",
        )


class ManagementMemoryWriteContractTest(unittest.TestCase):
    def _assert_checked_write(self, qualified_name: str, verify_response: str) -> None:
        body = _function_body("bau_systemB.cpp", qualified_name)
        authorization = body.find("!managementMemoryAccessAllowed()")
        destination = body.find("_memory.toAbsoluteChecked(memoryAddress, number)")
        invalid = _assert_contains(
            self,
            body,
            r"if\s*\([^)]*number\s*==\s*0[^)]*data\s*==\s*nullptr[^)]*"
            r"destination\s*==\s*nullptr[^)]*\)\s*(?:return\s*;|\{)",
            f"{qualified_name} must reject zero/null/out-of-range writes",
        )
        write = body.find("_memory.writeMemory(memoryAddress, number, data)")
        self.assertTrue(0 <= authorization < destination < invalid.start() < write)
        self.assertNotIn(verify_response + "number, memoryAddress, data", body[write:])
        self.assertIn(verify_response + "number, memoryAddress, destination", body[write:])

    def test_memory_router_verify_uses_checked_destination(self) -> None:
        self._assert_checked_write(
            "BauSystemB::memoryRouterWriteIndication",
            "memoryRouterReadIndication(priority, hopType, asap, secCtrl, ",
        )

    def test_memory_routing_table_verify_uses_checked_destination(self) -> None:
        self._assert_checked_write(
            "BauSystemB::memoryRoutingTableWriteIndication",
            "memoryRoutingTableReadIndication(priority, hopType, asap, secCtrl, ",
        )

    def test_memory_verify_uses_checked_destination(self) -> None:
        self._assert_checked_write(
            "BauSystemB::memoryWriteIndication",
            "memoryReadIndication(priority, hopType, asap, secCtrl, ",
        )

    def test_extended_memory_write_returns_checked_memory_only(self) -> None:
        body = _function_body("bau_systemB.cpp", "BauSystemB::memoryExtWriteIndication")
        authorization = body.find("!managementMemoryAccessAllowed()")
        destination = body.find("_memory.toAbsoluteChecked(memoryAddress, number)")
        invalid = body.find("destination == nullptr")
        write = body.find("_memory.writeMemory(memoryAddress, number, data)")
        response = body.rfind("ReturnCodes::Success")
        self.assertTrue(0 <= authorization < destination < invalid < write < response)
        self.assertIn("ReturnCodes::AddressVoid", body[destination:write])
        self.assertIn("number, memoryAddress, destination", body[response:])


class CemiBoundaryContractTest(unittest.TestCase):
    def test_raw_medium_lengths_exclude_cemi_additional_info(self) -> None:
        tp = _function_body("cemi_frame.cpp", "CemiFrame::telegramLengthtTP")
        self.assertIn("!_layoutValid", tp)
        self.assertIn("_data[1]", tp)
        self.assertRegex(tp, r"totalLenght\s*\(\s*\)\s*-\s*2\s*-\s*addInfoLen")
        self.assertRegex(tp, r"totalLenght\s*\(\s*\)\s*-\s*1\s*-\s*addInfoLen")

        rf = _function_body("cemi_frame.cpp", "CemiFrame::telegramLengthtRF")
        self.assertIn("!_layoutValid", rf)
        self.assertRegex(rf, r"3U?\s*\+\s*_data\s*\[\s*1\s*\]")
        self.assertRegex(rf, r"totalLenght\s*\(\s*\)\s*-\s*overhead")

    def test_raw_medium_fillers_reject_null_or_zero_length_before_writing(self) -> None:
        for function in ("CemiFrame::fillTelegramTP", "CemiFrame::fillTelegramRF"):
            with self.subTest(function=function):
                body = _function_body("cemi_frame.cpp", function)
                guard = _assert_contains(
                    self,
                    body,
                    r"if\s*\(\s*data\s*==\s*nullptr\s*\|\|\s*len\s*==\s*0\s*\)"
                    r"\s*return\s*;",
                    f"{function} must reject a null destination and an invalid frame length",
                )
                first_write = min(
                    position for position in (body.find("data[0]"), body.find("memcpy"))
                    if position >= 0
                )
                self.assertLess(guard.start(), first_write)

    def test_property_ext_description_read_uses_eight_octet_layout(self) -> None:
        body = _function_body("application_layer.cpp", "ApplicationLayer::individualIndication")
        case_start = body.find("case PropertyExtDescriptionRead")
        self.assertGreaterEqual(case_start, 0)
        case_end = body.find("case PropertyDescriptionResponse", case_start)
        self.assertGreater(case_end, case_start)
        branch = body[case_start:case_end]
        self.assertIn("apdu.length() < 8", branch)
        self.assertRegex(
            branch,
            r"propertyIndex\s*=\s*\(\(data\[6\]\s*&\s*0x0f\)\s*<<\s*8\)"
            r"\s*\|\s*\(data\[7\]\s*&\s*0xff\)",
        )
        self.assertNotIn("data[8]", branch)

    def test_usb_identity_constructor_arguments_match_declared_order(self) -> None:
        code = _read_code("cemi_server.cpp")
        self.assertRegex(
            code,
            r"_usbTunnelInterface\s*\(\s*\*this\s*,\s*"
            r"_bau\.deviceObject\(\)\.manufacturerId\(\)\s*,\s*"
            r"_bau\.deviceObject\(\)\.maskVersion\(\)\s*\)",
        )

    def test_rf_tunnel_indication_forwards_rebuilt_additional_info_frame(self) -> None:
        body = _function_body("cemi_server.cpp", "CemiServer::dataIndicationToTunnel")
        self.assertIn("dataIndicationToTunnel(tmpFrame)", body)
        self.assertNotIn("dataIndicationToTunnel(frame)", body)

    def test_external_constructor_validates_before_using_additional_info(self) -> None:
        body = _function_body("cemi_frame.cpp", "CemiFrame::CemiFrame")
        validation = body.find("validBuffer(data, length)")
        derived = body.find("data[1]", validation)
        self.assertTrue(0 <= validation < derived)
        self.assertIn("_data = buffer", body[validation:derived])
        self.assertIn("_length = 0", body[validation:derived])

    def test_cemi_server_drops_invalid_l_data_before_dispatch(self) -> None:
        body = _function_body("cemi_server.cpp", "CemiServer::frameReceived")
        envelope = body.find("CemiFrame::validBuffer")
        semantic = body.find("frame.valid()")
        dispatch = body.find("handleLData(frame)")
        self.assertTrue(0 <= envelope < semantic < dispatch)

    def test_property_read_bounds_patch_and_negative_copy(self) -> None:
        body = _function_body("cemi_server.cpp", "CemiServer::handleMPropRead")
        self.assertLess(body.find("frame.dataLength() < 7"), body.find("popWord"))
        self.assertRegex(body, r"data\s*!=\s*nullptr\s*&&\s*dataSize\s*>=\s*1")
        self.assertIn("startIndex != 0", body)
        self.assertIn("dataSize <= MAX_CEMI_FRAME_SIZE - 7", body)
        self.assertRegex(body, r"memcpy\s*\(\s*responseData\s*,\s*frame\.data\(\)\s*,\s*7\s*\)")
        self.assertIn("delete[] data", body)

    def test_property_write_probe_gate_and_collision(self) -> None:
        body = _function_body("cemi_server.cpp", "CemiServer::handleMPropWrite")
        guard = body.find("frame.dataLength() < 7")
        payload = body.find("frame.dataLength() - 7")
        self.assertTrue(0 <= guard < payload)
        self.assertIn("requestDataSize == 0", body)
        self.assertIn("!cemiManagementWriteAllowed(_bau)", body)
        self.assertIn("candidate == _bau.deviceObject().individualAddress()", body)
        self.assertRegex(body, r"memcpy\s*\(\s*responseData\s*,\s*frame\.data\(\)\s*,\s*7\s*\)")

    def test_reset_requires_management_window_before_persistent_write(self) -> None:
        body = _function_body("cemi_server.cpp", "CemiServer::handleMReset")
        gate = _assert_contains(
            self,
            body,
            r"if\s*\(\s*!cemiManagementWriteAllowed\s*\(\s*_bau\s*\)\s*\)"
            r"\s*return\s*;",
            "M_Reset_req must not commit persistent memory outside programming mode",
        )
        write = body.find("_bau.writeMemory()")
        response = body.find("M_Reset_ind")
        self.assertTrue(0 <= gate.start() < write < response)


class KnxIpTunnelBoundaryContractTest(unittest.TestCase):
    def test_connect_cri_length_is_connection_type_specific(self) -> None:
        body = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleIpFrame")
        connect = body[body.find("case ConnectRequest:"):
                       body.find("case ConnectionStateRequest:")]
        self.assertIn("length < criOffset + 2", connect)
        self.assertIn("connectionType == TUNNEL_CONNECTION && criLength == LEN_CRI", connect)
        self.assertIn("connectionType == DEVICE_MGMT_CONNECTION && criLength == 2", connect)
        self.assertIn("unknownType && criLength >= 2", connect)
        self.assertIn("criOffset + criLength != length", connect)
        self.assertNotIn("buffer[criOffset] < LEN_CRI", connect)

    def test_envelope_and_embedded_cemi_are_checked_before_handlers(self) -> None:
        body = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleIpFrame")
        envelope = body.find("validKnxIpEnvelope")
        config_cemi = body.find(
            "validDeviceConfigurationCemi", body.find("DeviceConfigurationRequest")
        )
        config_handler = body.find("HandleDeviceConfigurationRequest", config_cemi)
        tunnel_cemi = body.find("validTunnelingCemi", body.find("TunnelingRequest"))
        tunnel_handler = body.find("HandleTunnelingRequest", tunnel_cemi)
        self.assertTrue(0 <= envelope < config_cemi < config_handler)
        self.assertTrue(0 <= envelope < tunnel_cemi < tunnel_handler)

    def test_knxip_service_and_cemi_message_classes_are_not_interchangeable(self) -> None:
        config = _function_body("ip_tunnel_server.cpp", "validDeviceConfigurationCemi")
        for message in ("M_PropRead_req", "M_PropWrite_req", "M_Reset_req"):
            self.assertIn(message, config)
        for message in ("L_data_req", "L_data_con", "L_data_ind"):
            self.assertNotIn(message, config)
        self.assertRegex(config, r"default\s*:\s*return\s+false")

        tunneling = _function_body("ip_tunnel_server.cpp", "validTunnelingCemi")
        self.assertIn("validTunnelCemi", tunneling)
        self.assertIn("== L_data_req", tunneling)

    def test_generated_tunnel_addresses_remain_alive_until_assignment(self) -> None:
        body = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleConnectRequest")
        storage = body.find("fallbackAddresses")
        fallback = body.find("addresses = fallbackAddresses", storage)
        consume = body.find("popWord(tunPa, addresses", fallback)
        self.assertTrue(0 <= storage < fallback < consume)
        self.assertNotIn("addrbuffer", body)

    def test_outbound_tunnel_frame_is_copied_before_views_are_constructed(self) -> None:
        code = _read_code("knx_ip_tunneling_request.cpp")
        helper = _function_body("knx_ip_tunneling_request.cpp", "copyCemiFrame")
        self.assertIn("memcpy(destination, frame.data(), frame.totalLenght())", helper)
        self.assertRegex(
            code,
            r"_frame\s*\(\s*copyCemiFrame\s*\(\s*_data\s*\+\s*LEN_CH\s*\+\s*"
            r"LEN_KNXIP_HEADER\s*,\s*frame\s*\)\s*,\s*frame\.totalLenght\(\)\s*\)",
        )

        routing_code = _read_code("knx_ip_routing_indication.cpp")
        self.assertRegex(
            routing_code,
            r"_frame\s*\(\s*copyRoutingCemiFrame\s*\(\s*_data\s*\+\s*"
            r"LEN_KNXIP_HEADER\s*,\s*frame\s*\)\s*,\s*frame\.totalLenght\(\)\s*\)",
        )

    def _assert_endpoint_precedes_dispatch(self, function: str, dispatch: str) -> str:
        body = _function_body("ip_tunnel_server.cpp", function)
        endpoint = body.find("endpointMatches(tun, src_addr, src_port, false)")
        self.assertTrue(0 <= endpoint < body.find(dispatch))
        return body

    def test_data_request_is_endpoint_and_sequence_bound(self) -> None:
        body = self._assert_endpoint_precedes_dispatch(
            "IpTunnelServer::HandleTunnelingRequest", "_cemiServer.frameReceived"
        )
        self.assertLess(body.find("SequenceCounter_R"), body.find("_cemiServer.frameReceived"))
        self.assertIn("E_SEQUENCE_NUMBER", body)

    def test_tunnel_source_is_always_bound_to_authenticated_channel_address(self) -> None:
        body = _function_body(
            "ip_tunnel_server.cpp", "IpTunnelServer::HandleTunnelingRequest"
        )
        endpoint = body.find("endpointMatches(tun, src_addr, src_port, false)")
        bind = body.find("tunnReq.frame().sourceAddress(tun->IndividualAddress)")
        dispatch = body.find("_cemiServer.frameReceived")
        self.assertTrue(0 <= endpoint < bind < dispatch)
        self.assertNotIn("sourceAddress() == 0", body)

    def test_config_request_is_endpoint_and_sequence_bound(self) -> None:
        body = self._assert_endpoint_precedes_dispatch(
            "IpTunnelServer::HandleDeviceConfigurationRequest", "_cemiServer.frameReceived"
        )
        self.assertIn("sequence == tun->SequenceCounter_R", body)
        self.assertIn("(uint8_t)(sequence - 1) != tun->SequenceCounter_R", body)
        self.assertIn("E_SEQUENCE_NUMBER", body)

    def test_ack_is_endpoint_and_sequence_bound(self) -> None:
        body = _function_body(
            "ip_tunnel_server.cpp", "IpTunnelServer::HandleTunnelAcknowledgement"
        )
        self.assertIn("endpointMatches(tun, src_addr, src_port, false)", body)
        self.assertIn("tun->SequenceCounter_S - 1", body)

    def test_channel_ids_are_unique_across_data_and_management_slots(self) -> None:
        body = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleConnectRequest")
        self.assertRegex(
            body,
            r"for\s*\([^;]*x\s*=\s*0\s*;\s*x\s*<\s*KNX_TUNNELING\s*\+\s*"
            r"KNX_TUNNELING_DEVMGMT",
        )

    def test_timeout_loop_visits_every_tunnel_slot(self) -> None:
        body = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::loop")
        self.assertIn("KNX_TUNNELING + KNX_TUNNELING_DEVMGMT", body)
        self.assertNotRegex(body, r"\bbreak\s*;")

    def test_stateless_responses_cannot_reflect_to_claimed_ip(self) -> None:
        dispatch = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleIpFrame")
        self.assertGreaterEqual(dispatch.count("hpaiAddressMatchesSource"), 5)

        connect = _function_body("ip_tunnel_server.cpp", "IpTunnelServer::HandleConnectRequest")
        self.assertNotIn("sendBytesUniCast(connRequest.hpaiCtrl().ipAddress()", connect)
        self.assertIn("sendBytesUniCast(src_addr, responsePort", connect)

        description = _function_body(
            "ip_tunnel_server.cpp", "IpTunnelServer::HandleDescriptionRequest"
        )
        self.assertNotIn("sendBytesUniCast(descReq.hpaiCtrl().ipAddress()", description)
        self.assertIn("sendBytesUniCast(src_addr, responsePort", description)


class IpDataLinkBoundaryContractTest(unittest.TestCase):
    def test_datagram_and_service_payloads_are_validated_before_views(self) -> None:
        body = _function_body("ip_data_link_layer.cpp", "IpDataLinkLayer::loop")
        envelope = body.find("validKnxIpDatagram")
        service = body.find("switch ((KnxIpServiceType)code)")
        self.assertTrue(0 <= envelope < service)

        routing_case = body.find("case RoutingIndication")
        routing_validation = body.find("CemiFrame::validBuffer", routing_case)
        routing_view = body.find("KnxIpRoutingIndication routingIndication", routing_case)
        self.assertTrue(0 <= routing_case < routing_validation < routing_view)
        self.assertIn("!= L_data_ind", body[routing_case:routing_view])

        search_case = body.find("case SearchRequest:")
        search_guard = body.find("validSearchHpai", search_case)
        search_view = body.find("KnxIpSearchRequest searchRequest", search_case)
        self.assertTrue(0 <= search_case < search_guard < search_view)

    def test_search_responses_are_bound_to_actual_source_ip(self) -> None:
        body = _function_body("ip_data_link_layer.cpp", "IpDataLinkLayer::loop")
        classic = body[body.find("case SearchRequest:"):body.find("case SearchRequestExt:")]
        self.assertIn("validSearchHpai", classic)
        self.assertIn("sendBytesUniCast(remoteAddr, responsePort", classic)
        self.assertNotIn("sendBytesUniCast(hpai.ipAddress()", classic)

        extended = _function_body(
            "ip_data_link_layer.cpp", "IpDataLinkLayer::loopHandleSearchRequestExtended"
        )
        self.assertIn("searchRequest.valid()", extended)
        self.assertIn("_deviceObject.progMode()", extended)
        self.assertNotIn("knx.progMode()", extended)
        self.assertIn("sendBytesUniCast(remoteAddr, responsePort", extended)
        self.assertNotIn("sendBytesUniCast(searchRequest.hpai().ipAddress()", extended)

    def test_extended_search_srp_parser_fails_closed_on_bad_lengths(self) -> None:
        body = _function_body(
            "knx_ip_search_request_extended.cpp",
            "KnxIpSearchRequestExtended::KnxIpSearchRequestExtended",
        )
        length_guard = body.find("srpLength < 2")
        type_read = body.find("data[currentPos + 1]")
        advance = body.find("currentPos += srpLength")
        self.assertTrue(0 <= length_guard < type_read < advance)
        self.assertIn("srpLength > length - currentPos", body)
        self.assertNotIn("currentPos += data[currentPos]", body)

        header = _read_code("knx_ip_search_request_extended.h")
        self.assertRegex(
            header,
            r"bool\s+requestedDIBs\s*\[\s*REQUESTED_DIBS_MAX\s*\]\s*=\s*\{\s*false\s*\}",
        )
        self.assertIn("code >= REQUESTED_DIBS_MAX", _function_body(
            "knx_ip_search_request_extended.cpp",
            "KnxIpSearchRequestExtended::requestedDIB",
        ))

    def test_extended_search_bounds_dynamic_response_before_allocation(self) -> None:
        body = _function_body(
            "ip_data_link_layer.cpp", "IpDataLinkLayer::loopHandleSearchRequestExtended"
        )
        wide_length = body.find("uint32_t dibLength")
        allocation_guard = body.find("dibLength > maxDibLength")
        constructor = body.find("KnxIpSearchResponseExtended searchResponse")
        self.assertTrue(0 <= wide_length < allocation_guard < constructor)
        self.assertIn("500U - LEN_KNXIP_HEADER - LEN_IPHPAI", body)

        mac_lookup = body.find("Property* macProperty")
        null_guard = body.find("macProperty == nullptr", mac_lookup)
        mac_read = body.find("macProperty->read(localMac)", null_guard)
        compare = body.find("searchRequest.srpMacAddr[i]", mac_read)
        self.assertTrue(0 <= mac_lookup < null_guard < mac_read < compare)

        knx_addresses = body[body.find("requestedDIB(KNX_ADDRESSES)"):
                             body.find("requestedDIB(MANUFACTURER_DATA)")]
        self.assertIn("addresses != nullptr ? length : 0", knx_addresses)
        self.assertIn("addressCount * 2U", knx_addresses)

        tunnel_info = body[body.find("requestedDIB(TUNNELING_INFO)"):
                           body.find("#endif", body.find("requestedDIB(TUNNELING_INFO)"))]
        self.assertIn("addresses != nullptr ? length : KNX_TUNNELING", tunnel_info)
        self.assertIn("addressCount * 4U", tunnel_info)

    def test_extended_search_dib_encoders_use_effective_address_counts(self) -> None:
        knx_addresses = _function_body(
            "knx_ip_search_response_extended.cpp",
            "KnxIpSearchResponseExtended::setKnxAddresses",
        )
        pointer = knx_addresses.find("const uint8_t *addresses")
        count = knx_addresses.find("addressCount = addresses != nullptr ? length : 0")
        loop = knx_addresses.find("i < addressCount")
        dereference = knx_addresses.find("popWord(additional, addresses", loop)
        self.assertTrue(0 <= pointer < count < loop < dereference)

        tunneling = _function_body(
            "knx_ip_search_response_extended.cpp",
            "KnxIpSearchResponseExtended::setTunnelingInfo",
        )
        storage = tunneling.find("fallbackAddresses")
        selection = tunneling.find("addresses = configuredCount == KNX_TUNNELING", storage)
        fallback = tunneling.find("addresses = fallbackAddresses", selection)
        loop = tunneling.find("i < addressCount", fallback)
        self.assertTrue(0 <= storage < selection < fallback < loop)
        self.assertNotIn("addrbuffer", tunneling)

    def test_rate_limit_completes_request_and_uses_rolling_second(self) -> None:
        send = _function_body("ip_data_link_layer.cpp", "IpDataLinkLayer::sendFrame")
        validity = send.find("!frame.valid()")
        packet = send.find("KnxIpRoutingIndication packet")
        self.assertTrue(0 <= validity < packet)
        invalid_branch = send[validity:packet]
        self.assertIn("dataConReceived(frame, false)", invalid_branch)
        self.assertIn("return false", invalid_branch)

        limited = send[send.find("if(isSendLimitReached())"):send.find("bool success")]
        self.assertIn("dataConReceived(frame, false)", limited)
        self.assertLess(limited.find("dataConReceived(frame, false)"), limited.find("return false"))

        limiter = _function_body(
            "ip_data_link_layer.cpp", "IpDataLinkLayer::isSendLimitReached"
        )
        self.assertIn("curTime >= _frameCountTimeBase", limiter)
        self.assertIn("curTime - _frameCountTimeBase", limiter)
        self.assertIn("sum >= 50", limiter)
        self.assertNotIn("_frameCountTimeBase - curTime", limiter)


class UsbTunnelBoundaryContractTest(unittest.TestCase):
    def test_receive_checks_header_and_declared_length_before_enqueue(self) -> None:
        body = _function_body("usb_tunnel_interface.cpp", "UsbTunnelInterface::receiveHidReport")
        size_guard = body.find("bufSize < HID_HEADER_SIZE")
        first_read = body.find("data[0]")
        declared = body.find("packetLength > bufSize")
        enqueue = body.find("addBufferRxQueue")
        self.assertTrue(0 <= size_guard < first_read < declared < enqueue)

    def test_reassembly_is_bounded_and_uses_array_delete(self) -> None:
        body = _function_body(
            "usb_tunnel_interface.cpp", "UsbTunnelInterface::handleHidReportRxQueue"
        )
        self.assertIn("!loadNextRxBuffer", body)
        self.assertIn("packetLength > sizeof(tpPacket) - offset", body)
        self.assertNotRegex(body, r"(?<!\[\])delete\s+data")
        self.assertGreaterEqual(body.count("delete[] data"), 5)

    def test_transfer_declared_body_and_cemi_are_exact(self) -> None:
        body = _function_body(
            "usb_tunnel_interface.cpp", "UsbTunnelInterface::handleTransferProtocolPacket"
        )
        self.assertIn("length < PROTOCOL_HEADER_LENGTH", body)
        self.assertIn("bodyLength != length - PROTOCOL_HEADER_LENGTH", body)
        self.assertIn("CemiFrame::validBuffer", body)

    def test_tx_fragments_copy_only_the_remaining_payload(self) -> None:
        body = _function_body(
            "usb_tunnel_interface.cpp", "UsbTunnelInterface::sendKnxHidReport"
        )
        remaining = body.find("length - offset")
        copy = body.find("memcpy", remaining)
        self.assertTrue(0 <= remaining < copy)
        self.assertNotIn("MIN(length, maxData)", body)


class IpParameterResetContractTest(unittest.TestCase):
    def test_array_counts_are_cleared_and_scalar_defaults_restored(self) -> None:
        reset_array = _function_body("ip_parameter_object.cpp", "resetArray")
        self.assertIn("property->write(0, 1, noElements)", reset_array)
        self.assertNotIn("MaxElements", reset_array)

        body = _function_body("ip_parameter_object.cpp", "IpParameterObject::masterReset")
        for pid in (
            "PID_ADDITIONAL_INDIVIDUAL_ADDRESSES",
            "PID_CUSTOM_RESERVED_TUNNELS_CTRL",
            "PID_CUSTOM_RESERVED_TUNNELS_IP",
        ):
            self.assertIn(f"resetArray(property({pid}))", body)
        self.assertIn("resetScalar(property(PID_ROUTING_MULTICAST_ADDRESS), DEFAULT_MULTICAST_ADDR)", body)
        self.assertIn("resetScalar(property(PID_TTL), 16)", body)


class EspIdfIpByteOrderContractTest(unittest.TestCase):
    def test_socket_boundaries_convert_between_host_and_network_order(self) -> None:
        setup = _function_body("../espidf_platform.cpp", "EspIdfPlatform::setupMultiCast")
        receive = _function_body("../espidf_platform.cpp", "EspIdfPlatform::readBytesMultiCast")
        send = _function_body("../espidf_platform.cpp", "EspIdfPlatform::sendBytesUniCast")

        self.assertIn("_multicast_addr = htonl(addr)", setup)
        self.assertIn("imreq.imr_multiaddr.s_addr = _multicast_addr", setup)
        self.assertIn("src_addr = ntohl(_remote_addr->sin_addr.s_addr)", receive)
        self.assertIn("htonl(addr)", send)


class PropertyServiceResultContractTest(unittest.TestCase):
    def test_standard_write_rejects_with_zero_elements_before_read_response(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::propertyValueWriteIndication"
        )
        write = body.find("obj->writeProperty")
        response = body.find("propertyValueReadIndication")
        self.assertTrue(0 <= write < response)

        # One assignment covers a rejected property/payload/access check and the
        # other covers an unknown object.  Both must precede the read-response.
        rejected_counts = [
            match.start()
            for match in re.finditer(r"numberOfElements\s*=\s*0\s*;", body)
        ]
        self.assertGreaterEqual(len(rejected_counts), 2)
        self.assertTrue(all(write < position < response for position in rejected_counts))

        # A startIndex==0 property read can otherwise turn an input count of zero
        # back into one.  The response helper must preserve the failure sentinel.
        read_body = _function_body(
            "bau_systemB.cpp", "BauSystemB::propertyValueReadIndication"
        )
        read_call = read_body.find("obj->readProperty")
        zero_guard = read_body.rfind("elementCount > 0", 0, read_call)
        self.assertTrue(0 <= zero_guard < read_call)

    def test_extended_write_reports_callback_rejection_as_data_void(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::propertyValueExtWriteIndication"
        )
        local_count = _assert_contains(
            self,
            body,
            r"uint8_t\s+(\w+)\s*=\s*numberOfElements\s*;",
            "extended property writes need a local in/out element count",
        )
        count_name = local_count.group(1)
        write = _assert_contains(
            self,
            body,
            r"obj->writeProperty\s*\([^;]*\b" + re.escape(count_name) + r"\s*\)\s*;",
            "writeProperty must receive the local count by reference",
        )
        rejection = _assert_contains(
            self,
            body,
            r"if\s*\(\s*" + re.escape(count_name) + r"\s*==\s*0\s*\)"
            r"\s*\{[^{}]*returnCode\s*=\s*ReturnCodes::DataVoid\s*;"
            r"[^{}]*numberOfElements\s*=\s*0\s*;[^{}]*\}",
            "a property callback that writes zero elements must not confirm Success",
        )
        response = body.find("propertyValueExtWriteConResponse")
        self.assertTrue(local_count.start() < write.start() < rejection.start() < response)

    def test_extended_description_echoes_resolved_pid_and_index(self) -> None:
        body = _function_body(
            "bau_systemB.cpp", "BauSystemB::propertyExtDescriptionReadIndication"
        )
        resolve = body.find("readPropertyDescription(pid, pidx")
        response = body.find("propertyExtDescriptionReadResponse")
        self.assertTrue(0 <= resolve < response)
        response_args = body[response : body.find(";", response)]
        self.assertRegex(response_args, r"objectInstance\s*,\s*pid\s*,\s*pidx\s*,")
        self.assertNotRegex(
            response_args,
            r"objectInstance\s*,\s*propertyId\s*,\s*propertyIndex\s*,",
        )


class ApplicationLayerLengthContractTest(unittest.TestCase):
    def test_group_confirm_rejects_empty_apdu_before_type_and_length_math(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::dataGroupConfirm", occurrence=1
        )
        guard = body.find("apdu.length() < 1")
        dispatch = body.find("switch (apdu.type())")
        self.assertTrue(0 <= guard < dispatch)

    def test_individual_responses_are_guarded_before_payload_access(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::individualIndication"
        )
        dispatch = body.find("switch (apdu.type())")
        empty_guard = body.find("apdu.length() < 1")
        self.assertTrue(0 <= empty_guard < dispatch)

        for case_name, minimum, consumer in (
            ("UserManufacturerInfoResponse", 4, "userManufacturerInfoAppLayerConfirm"),
            ("AuthorizeResponse", 2, "authorizeAppLayerConfirm"),
            ("KeyResponse", 2, "keyWriteAppLayerConfirm"),
        ):
            case = body.find("case " + case_name)
            guard = body.find(f"apdu.length() < {minimum}", case)
            call = body.find(consumer, case)
            self.assertTrue(0 <= case < guard < call, f"missing {case_name} length guard")

    def test_serial_number_response_builder_reserves_entire_payload(self) -> None:
        body = _function_body(
            "application_layer.cpp",
            "ApplicationLayer::individualAddressSerialNumberReadResponse",
        )
        self.assertRegex(body, r"CemiFrame\s+frame\s*\(\s*9\s*\)")
        self.assertIn("pushWord(domainAddress, data)", body)

    def test_fixed_response_builders_do_not_pad_beyond_their_protocol_payload(self) -> None:
        for function, length in (
            ("ApplicationLayer::individualAddressSerialNumberWriteRequest", 9),
            ("ApplicationLayer::IndividualAddressSerialNumberReadResponse", 9),
            ("ApplicationLayer::keyWriteResponse", 2),
        ):
            body = _function_body("application_layer.cpp", function)
            self.assertRegex(body, rf"CemiFrame\s+frame\s*\(\s*{length}\s*\)")

    def test_property_read_builder_preserves_start_index_and_sets_count(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::propertyValueReadRequest"
        )
        frame = body.find("CemiFrame frame")
        self.assertLess(body.find("numberOfElements > 0x0f"), frame)
        self.assertLess(body.find("startIndex > 0x0fff"), frame)
        self.assertIn("pushWord(startIndex, data)", body)
        self.assertRegex(
            body,
            r"\*data\s*=\s*\(\s*\*data\s*&\s*0x0f\s*\)\s*\|\s*"
            r"\(\s*numberOfElements\s*<<\s*4\s*\)",
        )
        self.assertNotRegex(body, r"\*data\s*&=")

    def test_memory_read_builders_reject_unencodable_fields(self) -> None:
        memory = _function_body(
            "application_layer.cpp", "ApplicationLayer::memoryReadRequest"
        )
        self.assertLess(memory.find("number > 0x3f"), memory.find("CemiFrame frame"))

        user = _function_body(
            "application_layer.cpp", "ApplicationLayer::userMemoryReadRequest"
        )
        frame = user.find("CemiFrame frame")
        self.assertLess(user.find("number > 0x0f"), frame)
        self.assertLess(user.find("memoryAddress > 0x000fffff"), frame)
        self.assertIn("pushWord(memoryAddress & 0xffff, data + 2)", user)

    def test_manufacturer_info_builder_uses_matching_response_apci(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::userManufacturerInfoReadResponse"
        )
        self.assertIn("apdu.type(UserManufacturerInfoResponse)", body)
        self.assertNotIn("apdu.type(UserMemoryRead)", body)

    def test_variable_property_builders_reject_oversize_and_null_payloads(self) -> None:
        for function, overhead in (
            ("ApplicationLayer::propertyDataSend", 5),
            ("ApplicationLayer::propertyExtDataSend", 9),
        ):
            body = _function_body("application_layer.cpp", function)
            frame = body.find("CemiFrame frame")
            size_guard = body.find(f"length > MAX_APDU_OCTET_COUNT - {overhead}")
            null_guard = body.find("length > 0 && data == nullptr")
            self.assertTrue(
                0 <= size_guard < frame and 0 <= null_guard < frame,
                f"{function} must reject invalid payloads before frame construction",
            )

    def test_function_result_builders_reject_instead_of_truncating(self) -> None:
        for function, overhead in (
            ("ApplicationLayer::functionPropertyStateResponse", 3),
            ("ApplicationLayer::functionPropertyExtStateResponse", 6),
        ):
            body = _function_body("application_layer.cpp", function)
            frame = body.find("CemiFrame frame")
            self.assertLess(
                body.find(f"resultLength > MAX_APDU_OCTET_COUNT - {overhead}"), frame
            )
            self.assertLess(body.find("resultData == nullptr"), frame)
            self.assertNotRegex(body[:frame], r"resultLength\s*=\s*")

    def test_memory_builders_enforce_encoded_count_width_before_frame(self) -> None:
        for function, maximum in (
            ("ApplicationLayer::memorySend", "0x3f"),
            ("ApplicationLayer::memoryRouterSend", "0x0f"),
            ("ApplicationLayer::memoryRoutingTableSend", "0x0f"),
            ("ApplicationLayer::userMemorySend", "0x0f"),
        ):
            body = _function_body("application_layer.cpp", function)
            frame = body.find("CemiFrame frame")
            self.assertLess(body.find(f"number > {maximum}"), frame)
            self.assertLess(body.find("number > 0 && memoryData == nullptr"), frame)

    def test_group_and_extended_memory_builders_are_bounded(self) -> None:
        group = _function_body("application_layer.cpp", "ApplicationLayer::groupValueSend")
        group_frame = group.find("CemiFrame frame")
        self.assertLess(group.find("data == nullptr"), group_frame)
        self.assertLess(
            group.find("dataLength > MAX_APDU_OCTET_COUNT - 1"), group_frame
        )

        ext = _function_body(
            "application_layer.cpp", "ApplicationLayer::memoryExtReadResponse"
        )
        ext_frame = ext.find("CemiFrame frame")
        self.assertLess(ext.find("number > MAX_APDU_OCTET_COUNT - 5"), ext_frame)
        self.assertLess(ext.find("number > 0 && memoryData == nullptr"), ext_frame)
        self.assertNotRegex(ext[:ext_frame], r"number\s*=\s*")

    def test_routing_table_read_rejects_unencodable_count(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::individualIndication"
        )
        case = body.find("case RoutingTableRead:")
        guard = body.find("data[1] > 0x0f", case)
        dispatch = body.find("memoryRoutingTableReadIndication", case)
        self.assertTrue(0 <= case < guard < dispatch)

        for case_name, consumer in (
            ("MemoryRouterWrite", "memoryRouterWriteIndication"),
            ("MemoryRouterReadResponse", "memoryRouterReadAppLayerConfirm"),
            ("RoutingTableReadResponse", "memoryRoutingTableReadAppLayerConfirm"),
            ("RoutingTableWrite", "memoryRoutingTableWriteIndication"),
        ):
            case = body.find("case " + case_name + ":")
            guard = body.find("data[1] > 0x0f", case)
            dispatch = body.find(consumer, case)
            self.assertTrue(0 <= case < guard < dispatch)

    def test_user_memory_response_payload_matches_encoded_count(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::individualIndication"
        )
        case = body.find("case UserMemoryResponse:")
        guard = body.find("(data[1] & 0x0f) > apdu.length() - 4", case)
        dispatch = body.find("userMemoryReadAppLayerConfirm", case)
        self.assertTrue(0 <= case < guard < dispatch)

    def test_individual_confirm_checks_every_variable_payload_before_access(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::individualConfirm"
        )
        for case_name, guard_text, consumer in (
            ("PropertyValueRead", "apdu.length() < 5", "propertyValueReadLocalConfirm"),
            ("PropertyValueResponse", "apdu.length() < 5", "propertyValueReadResponseConfirm"),
            ("PropertyDescriptionRead", "apdu.length() < 4", "propertyDescriptionReadLocalConfirm"),
            ("PropertyExtDescriptionRead", "apdu.length() < 8", "propertyExtDescriptionReadLocalConfirm"),
            ("PropertyDescriptionResponse", "apdu.length() < 8", "propertyDescriptionReadResponseConfirm"),
            ("MemoryRead", "apdu.length() < 3", "memoryReadLocalConfirm"),
            ("MemoryResponse", "apdu.length() < 3", "memoryReadResponseConfirm"),
            ("MemoryWrite", "apdu.length() < 3", "memoryWriteLocalConfirm"),
            ("MemoryExtRead", "apdu.length() < 5", "memoryExtReadLocalConfirm"),
            ("MemoryExtReadResponse", "apdu.length() < 5", "memoryExtReadResponseConfirm"),
            ("MemoryExtWrite", "apdu.length() < 5", "memoryExtWriteLocalConfirm"),
            ("MemoryExtWriteResponse", "apdu.length() < 5", "memoryExtWriteResponseConfirm"),
            ("UserMemoryRead", "apdu.length() < 4", "memoryReadLocalConfirm"),
            ("UserMemoryResponse", "apdu.length() < 4", "memoryReadResponseConfirm"),
            ("UserMemoryWrite", "apdu.length() < 4", "memoryWriteLocalConfirm"),
            ("AuthorizeRequest", "apdu.length() < 6", "authorizeLocalConfirm"),
            ("KeyWrite", "apdu.length() < 6", "keyWriteLocalConfirm"),
        ):
            case = body.find("case " + case_name + ":")
            guard = body.find(guard_text, case)
            call = body.find(consumer, case)
            self.assertTrue(0 <= case < guard < call, f"missing guard for {case_name}")

    def test_extended_property_legacy_api_rejects_12_bit_aliases(self) -> None:
        body = _function_body(
            "application_layer.cpp", "ApplicationLayer::individualIndication"
        )
        cases = (
            ("PropertyValueExtRead", "PropertyValueExtWriteCon"),
            ("PropertyValueExtWriteCon", "FunctionPropertyCommand"),
            ("FunctionPropertyExtCommand", "FunctionPropertyExtState"),
            ("FunctionPropertyExtState", "PropertyDescriptionRead"),
        )
        for case_name, next_case in cases:
            with self.subTest(case=case_name):
                start = body.find("case " + case_name)
                end = body.find("case " + next_case, start + 1)
                branch = body[start:end]
                self.assertIn("uint16_t objectInstance", branch)
                self.assertIn("uint16_t propertyId", branch)
                guard = branch.find("objectInstance > 0xff || propertyId > 0xff")
                dispatch = branch.find("_bau.")
                self.assertTrue(0 <= guard < dispatch)
                self.assertIn("static_cast<uint8_t>(objectInstance)", branch)
                self.assertIn("static_cast<uint8_t>(propertyId)", branch)


class NpduMaximumLengthContractTest(unittest.TestCase):
    def test_npdu_length_does_not_wrap_at_maximum_apdu(self) -> None:
        header = _read_code("npdu.h")
        self.assertRegex(header, r"uint16_t\s+length\s*\(\s*\)\s*const")
        body = _function_body("npdu.cpp", "NPDU::length")
        self.assertIn("static_cast<uint16_t>", body)


class LinkLayerOutboundValidationContractTest(unittest.TestCase):
    def test_ip_rejects_invalid_cemi_before_routing_packet_construction(self) -> None:
        body = _function_body("ip_data_link_layer.cpp", "IpDataLinkLayer::sendFrame")
        guard = body.find("!frame.valid()")
        negative = body.find("dataConReceived(frame, false)", guard)
        packet = body.find("KnxIpRoutingIndication packet")
        self.assertTrue(0 <= guard < negative < packet)

    def test_rf_rejects_invalid_cemi_before_frame_metadata_and_queueing(self) -> None:
        body = _function_body("rf_data_link_layer.cpp", "RfDataLinkLayer::sendFrame")
        guard = body.find("!frame.valid()")
        negative = body.find("dataConReceived(frame, false)", guard)
        metadata = body.find("frame.rfSerialOrDoA()")
        queue = body.find("addFrameTxQueue")
        self.assertTrue(0 <= guard < negative < metadata < queue)

    def test_rf_rejects_unencodable_lengths_before_queue_and_positive_confirm(self) -> None:
        helper = _function_body("rf_data_link_layer.cpp", "rfPacketLengthFitsMedium")
        self.assertIn("const uint16_t lField = 9U + telegramLength", helper)
        self.assertIn("lField > 0xFFU", helper)
        self.assertIn("packetLength > 255U", helper)

        body = _function_body("rf_data_link_layer.cpp", "RfDataLinkLayer::sendFrame")
        validation = body.find("!rfPacketLengthFitsMedium")
        queue = body.find("addFrameTxQueue")
        positive = body.find("dataConReceived(frame, true)")
        rejected = body.find("dataConReceived(frame, false)", validation)
        self.assertTrue(0 <= validation < rejected < queue < positive)

    def test_rf_queue_allocation_matches_ft3_block_count_at_16_byte_boundary(self) -> None:
        body = _function_body("rf_data_link_layer.cpp", "RfDataLinkLayer::addFrameTxQueue")
        self.assertRegex(body, r"blockCount\s*=\s*\(length\s*\+\s*15U?\)\s*/\s*16U?")
        self.assertRegex(
            body,
            r"totalLength\s*=\s*12U?\s*\+\s*length\s*\+\s*2U?\s*\*\s*blockCount",
        )
        self.assertNotIn("bytesLeft + 2", body)


class RfTransmitOwnershipContractTest(unittest.TestCase):
    def test_cc1101_validates_queue_buffer_and_releases_array_on_every_exit(self) -> None:
        body = _function_body("rf_physical_layer_cc1101.cpp", "RfPhysicalLayerCC1101::loop")
        tx_start = body[body.find("case TX_START:"):body.find("case TX_ACTIVE:")]
        guard = tx_start.find("sendBuffer == nullptr || sendBufferLength == 0")
        packet_size = tx_start.find("PACKET_SIZE(sendBuffer[0])")
        self.assertTrue(0 <= guard < packet_size)
        self.assertIn("pktLen != sendBufferLength", tx_start)
        self.assertGreaterEqual(tx_start.count("delete[] sendBuffer"), 2)
        self.assertGreaterEqual(tx_start.count("_loopState = RX_START"), 2)

        tx_end = body[body.find("case TX_END:"):body.find("case RX_START:")]
        self.assertIn("delete[] sendBuffer", tx_end)
        self.assertIn("sendBuffer = nullptr", tx_end)
        self.assertIn("sendBufferLength = 0", tx_end)
        self.assertNotRegex(body, r"\bdelete\s+sendBuffer\s*;")

        stop = _function_body(
            "rf_physical_layer_cc1101.cpp", "RfPhysicalLayerCC1101::stopChip"
        )
        self.assertIn("delete[] sendBuffer", stop)
        self.assertIn("sendBuffer = nullptr", stop)
        self.assertIn("_loopState = RX_START", stop)

    def test_cc1310_guards_before_dereference_and_cleans_each_tx_exit(self) -> None:
        body = _function_body("rf_physical_layer_cc1310.cpp", "RfPhysicalLayerCC1310::loop")
        tx = body[body.find("case TX_START:"):body.find("case RX_START:")]
        guard = tx.find("sendBuffer == nullptr || sendBufferLength == 0")
        packet_size = tx.find("PACKET_SIZE(sendBuffer[0])")
        self.assertTrue(0 <= guard < packet_size)
        self.assertIn("pktLen != sendBufferLength", tx)
        # null/empty, L-field mismatch, general length, hardware limit and
        # successful send each consume the new[] allocation exactly once.
        self.assertGreaterEqual(tx.count("delete[] sendBuffer"), 5)
        self.assertGreaterEqual(tx.count("_loopState = RX_START"), 5)
        self.assertNotRegex(tx, r"\bdelete\s+sendBuffer\s*;")


if __name__ == "__main__":
    unittest.main(verbosity=2)
