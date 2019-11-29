/// `enum ObjectType` and the numbers used in `ObjectType::parse` are taken from the bacnet-stack
/// project, `bacenum.h` with minor modifications.
///
/// --- original copyright notice from bacenum.h ---
///
/// Copyright (C) 2012 Steve Karg <skarg@users.sourceforge.net>
///
/// Permission is hereby granted, free of charge, to any person obtaining
/// a copy of this software and associated documentation files (the
/// "Software"), to deal in the Software without restriction, including
/// without limitation the rights to use, copy, modify, merge, publish,
/// distribute, sublicense, and/or sell copies of the Software, and to
/// permit persons to whom the Software is furnished to do so, subject to
/// the following conditions:
///
/// The above copyright notice and this permission notice shall be included
/// in all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
/// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
/// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
/// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
/// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
///
///   Modifications Copyright (C) 2017 BACnet Interoperability Testing Services, Inc.
///
///   July 1, 2017    BITS    Modifications to this file have been made in compliance
///                           with original licensing.
///
///   This file contains changes made by BACnet Interoperability Testing
///   Services, Inc. These changes are subject to the permissions,
///   warranty terms and limitations above.
///   For more information: info@bac-test.com
///   For access to source code:  info@bac-test.com
///          or      www.github.com/bacnettesting/bacnet-stack
use arrayref::array_ref;

pub enum ObjectType {
    ObjectAnalogInput,
    ObjectAnalogOutput,
    ObjectAnalogValue,
    ObjectBinaryInput,
    ObjectBinaryOutput,
    ObjectBinaryValue,
    ObjectCalendar,
    ObjectCommand,
    ObjectDevice,
    ObjectEventEnrollment,
    ObjectFile,
    ObjectGroup,
    ObjectLoop,
    ObjectMultiStateInput,
    ObjectMultiStateOutput,
    ObjectNotificationClass,
    ObjectProgram,
    ObjectSchedule,
    ObjectAveraging,
    ObjectMultiStateValue,
    ObjectTrendlog,
    ObjectLifeSafetyPoint,
    ObjectLifeSafetyZone,
    ObjectAccumulator,
    ObjectPulseConverter,
    ObjectEventLog,
    ObjectGlobalGroup,
    ObjectTrendLogMultiple,
    ObjectLoadControl,
    ObjectStructuredView,
    ObjectAccessDoor,
    ObjectTimer,
    ObjectAccessCredential, /* addendum 2008-j */
    ObjectAccessPoint,
    ObjectAccessRights,
    ObjectAccessUser,
    ObjectAccessZone,
    ObjectCredentialDataInput,   /* authentication-factor-input */
    ObjectNetworkSecurity,       /* Addendum 2008-g */
    ObjectBitstringValue,        /* Addendum 2008-w */
    ObjectCharacterstringValue,  /* Addendum 2008-w */
    ObjectDatePatternValue,      /* Addendum 2008-w */
    ObjectDateValue,             /* Addendum 2008-w */
    ObjectDatetimePatternValue,  /* Addendum 2008-w */
    ObjectDatetimeValue,         /* Addendum 2008-w */
    ObjectIntegerValue,          /* Addendum 2008-w */
    ObjectLargeAnalogValue,      /* Addendum 2008-w */
    ObjectOctetstringValue,      /* Addendum 2008-w */
    ObjectPositiveIntegerValue,  /* Addendum 2008-w */
    ObjectTimePatternValue,      /* Addendum 2008-w */
    ObjectTimeValue,             /* Addendum 2008-w */
    ObjectNotificationForwarder, /* Addendum 2010-af */
    ObjectAlertEnrollment,       /* Addendum 2010-af */
    ObjectChannel,               /* Addendum 2010-aa */
    ObjectLightingOutput,        /* Addendum 2010-i */
    ObjectBinaryLightingOutput,  /* Addendum 135-2012az */
    ObjectNetworkPort,           /* Addendum 135-2012az */
    /* Enumerated values 0-127 are reserved for definition by ASHRAE. */
    /* Enumerated values 128-1023 may be used by others subject to  */
    /* the procedures and constraints described in Clause 23. */
    /* do the max range inside of enum so that
       compilers will allocate adequate sized datatype for enum
       which is used to store decoding */
    Reserved,
    Proprietary,
    Invalid,
}

impl ObjectType {
    pub fn parse(b: &[u8]) -> Self {
        // FIXME: parse properly
        match u16::from_be_bytes(*array_ref!(b, 0, 2)) {
            0 => Self::ObjectAnalogInput,
            1 => Self::ObjectAnalogOutput,
            2 => Self::ObjectAnalogValue,
            3 => Self::ObjectBinaryInput,
            4 => Self::ObjectBinaryOutput,
            5 => Self::ObjectBinaryValue,
            6 => Self::ObjectCalendar,
            7 => Self::ObjectCommand,
            8 => Self::ObjectDevice,
            9 => Self::ObjectEventEnrollment,
            10 => Self::ObjectFile,
            11 => Self::ObjectGroup,
            12 => Self::ObjectLoop,
            13 => Self::ObjectMultiStateInput,
            14 => Self::ObjectMultiStateOutput,
            15 => Self::ObjectNotificationClass,
            16 => Self::ObjectProgram,
            17 => Self::ObjectSchedule,
            18 => Self::ObjectAveraging,
            19 => Self::ObjectMultiStateValue,
            20 => Self::ObjectTrendlog,
            21 => Self::ObjectLifeSafetyPoint,
            22 => Self::ObjectLifeSafetyZone,
            23 => Self::ObjectAccumulator,
            24 => Self::ObjectPulseConverter,
            25 => Self::ObjectEventLog,
            26 => Self::ObjectGlobalGroup,
            27 => Self::ObjectTrendLogMultiple,
            28 => Self::ObjectLoadControl,
            29 => Self::ObjectStructuredView,
            30 => Self::ObjectAccessDoor,
            31 => Self::ObjectTimer,
            32 => Self::ObjectAccessCredential,
            33 => Self::ObjectAccessPoint,
            34 => Self::ObjectAccessRights,
            35 => Self::ObjectAccessUser,
            36 => Self::ObjectAccessZone,
            37 => Self::ObjectCredentialDataInput,
            38 => Self::ObjectNetworkSecurity,
            39 => Self::ObjectBitstringValue,
            40 => Self::ObjectCharacterstringValue,
            41 => Self::ObjectDatePatternValue,
            42 => Self::ObjectDateValue,
            43 => Self::ObjectDatetimePatternValue,
            44 => Self::ObjectDatetimeValue,
            45 => Self::ObjectIntegerValue,
            46 => Self::ObjectLargeAnalogValue,
            47 => Self::ObjectOctetstringValue,
            48 => Self::ObjectPositiveIntegerValue,
            49 => Self::ObjectTimePatternValue,
            50 => Self::ObjectTimeValue,
            51 => Self::ObjectNotificationForwarder,
            52 => Self::ObjectAlertEnrollment,
            53 => Self::ObjectChannel,
            54 => Self::ObjectLightingOutput,
            55 => Self::ObjectBinaryLightingOutput,
            56 => Self::ObjectNetworkPort,
            57..=127 => Self::Reserved,
            128..=1023 => Self::Proprietary,
            _ => Self::Invalid,
        }
    }
}
