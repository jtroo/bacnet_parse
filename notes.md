Current TODOs:
* Figure out if I finished tag parsing or not (I think I did not)
* Complete the parsing of a WHO-IS frame
* Complete the parsing of an I-AM frame

code below is from the bacnet stack - apdu handling
summary of notes on PDU type:
* confirmed request has non-trivial decoding to get service choice, data, request, etc.
* unfonfirmed request has easy service request - need to look at Unconfirmed_Function table
* simple ack delegates to handlers - parsing service choice is trivial
* complex ack is same as simple ack with additional logic to know if it's the last or not
* unsure what segment ack does. needs further reading
* reject and abort seem both pretty trivial
* error is a bit more complicated
```
            case PDU_TYPE_CONFIRMED_SERVICE_REQUEST:
                (void)apdu_decode_confirmed_service_request(&apdu[0],
                    apdu_len, &service_data, &service_choice, &service_request,
                    &service_request_len);
                if (apdu_confirmed_dcc_disabled(service_choice)) {
                    /* When network communications are completely disabled,
                       only DeviceCommunicationControl and ReinitializeDevice APDUs
                       shall be processed and no messages shall be initiated. */
                    break;
                }
                if ((service_choice < MAX_BACNET_CONFIRMED_SERVICE) &&
                    (Confirmed_Function[service_choice]))
                    Confirmed_Function[service_choice] (service_request,
                        service_request_len, src, &service_data);
                else if (Unrecognized_Service_Handler)
                    Unrecognized_Service_Handler(service_request,
                        service_request_len, src, &service_data);
                break;
            case PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
                service_choice = apdu[1];
                service_request = &apdu[2];
                service_request_len = apdu_len - 2;
                if (apdu_unconfirmed_dcc_disabled(service_choice)) {
                    /* When network communications are disabled,
                       only DeviceCommunicationControl and ReinitializeDevice APDUs
                       shall be processed and no messages shall be initiated.
                       If communications have been initiation disabled, then
                       WhoIs may be processed. */
                    break;
                }
                if (service_choice < MAX_BACNET_UNCONFIRMED_SERVICE) {
                    if (Unconfirmed_Function[service_choice])
                        Unconfirmed_Function[service_choice] (service_request,
                            service_request_len, src);
                }
                break;
            case PDU_TYPE_SIMPLE_ACK:
                invoke_id = apdu[1];
                service_choice = apdu[2];
                switch (service_choice) {
                    case SERVICE_CONFIRMED_ACKNOWLEDGE_ALARM:
                    case SERVICE_CONFIRMED_COV_NOTIFICATION:
                    case SERVICE_CONFIRMED_EVENT_NOTIFICATION:
                    case SERVICE_CONFIRMED_SUBSCRIBE_COV:
                    case SERVICE_CONFIRMED_SUBSCRIBE_COV_PROPERTY:
                    case SERVICE_CONFIRMED_LIFE_SAFETY_OPERATION:
                        /* Object Access Services */
                    case SERVICE_CONFIRMED_ADD_LIST_ELEMENT:
                    case SERVICE_CONFIRMED_REMOVE_LIST_ELEMENT:
                    case SERVICE_CONFIRMED_DELETE_OBJECT:
                    case SERVICE_CONFIRMED_WRITE_PROPERTY:
                    case SERVICE_CONFIRMED_WRITE_PROP_MULTIPLE:
                        /* Remote Device Management Services */
                    case SERVICE_CONFIRMED_DEVICE_COMMUNICATION_CONTROL:
                    case SERVICE_CONFIRMED_REINITIALIZE_DEVICE:
                    case SERVICE_CONFIRMED_TEXT_MESSAGE:
                        /* Virtual Terminal Services */
                    case SERVICE_CONFIRMED_VT_CLOSE:
                        /* Security Services */
                    case SERVICE_CONFIRMED_REQUEST_KEY:
                        if (Confirmed_ACK_Function[service_choice] != NULL) {
                            ((confirmed_simple_ack_function)
                                Confirmed_ACK_Function[service_choice]) (src,
                                invoke_id);
                        }
                        tsm_free_invoke_id(invoke_id);
                        break;
                    default:
                        break;
                }
                break;
            case PDU_TYPE_COMPLEX_ACK:
                service_ack_data.segmented_message =
                    (apdu[0] & BIT(3)) ? true : false;
                service_ack_data.more_follows =
                    (apdu[0] & BIT(2)) ? true : false;
                invoke_id = service_ack_data.invoke_id = apdu[1];
                len = 2;
                if (service_ack_data.segmented_message) {
                    service_ack_data.sequence_number = apdu[len++];
                    service_ack_data.proposed_window_number = apdu[len++];
                }
                service_choice = apdu[len++];
                service_request = &apdu[len];
                service_request_len = apdu_len - (uint16_t) len;
                switch (service_choice) {
                    case SERVICE_CONFIRMED_GET_ALARM_SUMMARY:
                    case SERVICE_CONFIRMED_GET_ENROLLMENT_SUMMARY:
                    case SERVICE_CONFIRMED_GET_EVENT_INFORMATION:
                        /* File Access Services */
                    case SERVICE_CONFIRMED_ATOMIC_READ_FILE:
                    case SERVICE_CONFIRMED_ATOMIC_WRITE_FILE:
                        /* Object Access Services */
                    case SERVICE_CONFIRMED_CREATE_OBJECT:
                    case SERVICE_CONFIRMED_READ_PROPERTY:
                    case SERVICE_CONFIRMED_READ_PROP_CONDITIONAL:
                    case SERVICE_CONFIRMED_READ_PROP_MULTIPLE:
                    case SERVICE_CONFIRMED_READ_RANGE:
                    case SERVICE_CONFIRMED_PRIVATE_TRANSFER:
                        /* Virtual Terminal Services */
                    case SERVICE_CONFIRMED_VT_OPEN:
                    case SERVICE_CONFIRMED_VT_DATA:
                        /* Security Services */
                    case SERVICE_CONFIRMED_AUTHENTICATE:
                        if (Confirmed_ACK_Function[service_choice] != NULL) {
                            (Confirmed_ACK_Function[service_choice])
                                (service_request, service_request_len, src,
                                &service_ack_data);
                        }
                        tsm_free_invoke_id(invoke_id);
                        break;
                    default:
                        break;
                }
                break;
            case PDU_TYPE_SEGMENT_ACK:
                /* FIXME: what about a denial of service attack here?
                   we could check src to see if that matched the tsm */
                tsm_free_invoke_id(invoke_id);
                break;
            case PDU_TYPE_ERROR:
                invoke_id = apdu[1];
                service_choice = apdu[2];
                len = 3;

                /* FIXME: Currently special case for C_P_T but there are others which may
                   need consideration such as ChangeList-Error, CreateObject-Error,
                   WritePropertyMultiple-Error and VTClose_Error but they may be left as
                   is for now until support for these services is added */

                if (service_choice == SERVICE_CONFIRMED_PRIVATE_TRANSFER) {     /* skip over opening tag 0 */
                    if (decode_is_opening_tag_number(&apdu[len], 0)) {
                        len++;  /* a tag number of 0 is not extended so only one octet */
                    }
                }
                len +=
                    decode_tag_number_and_value(&apdu[len], &tag_number,
                    &len_value);
                /* FIXME: we could validate that the tag is enumerated... */
                len += decode_enumerated(&apdu[len], len_value, &error_class);
                len +=
                    decode_tag_number_and_value(&apdu[len], &tag_number,
                    &len_value);
                /* FIXME: we could validate that the tag is enumerated... */
                len += decode_enumerated(&apdu[len], len_value, &error_code);

                if (service_choice == SERVICE_CONFIRMED_PRIVATE_TRANSFER) {     /* skip over closing tag 0 */
                    if (decode_is_closing_tag_number(&apdu[len], 0)) {
                        len++;  /* a tag number of 0 is not extended so only one octet */
                    }
                }
                if (service_choice < MAX_BACNET_CONFIRMED_SERVICE) {
                    if (Error_Function[service_choice])
                        Error_Function[service_choice] (src, invoke_id,
                            (BACNET_ERROR_CLASS) error_class,
                            (BACNET_ERROR_CODE) error_code);
                }
                tsm_free_invoke_id(invoke_id);
                break;
            case PDU_TYPE_REJECT:
                invoke_id = apdu[1];
                reason = apdu[2];
                if (Reject_Function)
                    Reject_Function(src, invoke_id, reason);
                tsm_free_invoke_id(invoke_id);
                break;
            case PDU_TYPE_ABORT:
                server = apdu[0] & 0x01;
                invoke_id = apdu[1];
                reason = apdu[2];
                if (Abort_Function)
                    Abort_Function(src, invoke_id, reason, server);
                tsm_free_invoke_id(invoke_id);
```
