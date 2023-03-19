local operations = {
        [0x1001] = "GetDeviceInfo",
        [0x1002] = "OpenSession",
        [0x1003] = "CloseSession",
        [0x1004] = "GetStorageIDs",
        [0x1005] = "GetStorageInfo",
        [0x1006] = "GetNumObjects",
        [0x1007] = "GetObjectHandles",
        [0x1008] = "GetObjectInfo",
        [0x1009] = "GetObject",
        [0x100A] = "GetThumb",
        [0x100B] = "DeleteObject",
        [0x100C] = "SendObjectInfo",
        [0x100D] = "SendObject",
        [0x100E] = "InitiateCapture",
        [0x100F] = "FormatStore",
        [0x1014] = "GetDevicePropDesc",
        [0x1015] = "GetDevicePropValue",
        [0x1016] = "SetDevicePropValue",
        [0x101B] = "ResetDevice",
        [0x9101] = "GetObjectPropsSupported",
        [0x9102] = "GetObjectPropDesc",
        [0x9103] = "GetObjectPropValue",
        [0x9104] = "SetObjectPropValue",
        [0x9105] = "GetInterdependentPropDesc",
        [0x9106] = "SendObjectPropList",
        [0x9107] = "GetObjectReferences",
        [0x9108] = "SetObjectReferences",
        [0x9109] = "Skip",
        [0x910A] = "GetObjectPropList",
        [0x9114] = "GetPartialObject",
        [0x9115] = "InitiateOpenCapture",
        [0x9116] = "InitiateTransfer",
        [0x9117] = "GetServiceIDs",
        [0x9118] = "GetServiceInfo",
        [0x9119] = "GetServiceCapabilities",
        [0x911A] = "GetDevicePropValueByForm",
        [0x911B] = "GetDevicePropValueArray",
        [0x911C] = "SetDevicePropValueArray",
        [0x911D] = "GetExtendedDeviceInfo",
        [0x911E] = "SendPartialObject",
        [0x911F] = "TruncateObject",
}

local response_codes = {
        [0x2001] = "OK",
        [0x2002] = "GeneralError",
        [0x2003] = "SessionNotOpen",
        [0x2004] = "InvalidTransactionID",
        [0x2005] = "OperationNotSupported",
        [0x2006] = "ParameterNotSupported",
        [0x2007] = "IncompleteTransfer",
        [0x2008] = "InvalidStorageID",
        [0x2009] = "InvalidObjectHandle",
        [0x200A] = "DevicePropNotSupported",
        [0x200B] = "InvalidObjectFormatCode",
        [0x200C] = "StoreFull",
        [0x200D] = "ObjectWriteProtected",
        [0x200E] = "StoreReadOnly",
        [0x200F] = "AccessDenied",
        [0x2010] = "NoThumbnailPresent",
        [0x2011] = "SelfTestFailed",
        [0x2012] = "PartialDeletion",
        [0x2013] = "StoreNotAvailable",
        [0x2014] = "SpecificationByFormatUnsupported",
        [0x2015] = "NoValidObjectInfo",
        [0x2016] = "InvalidCodeFormat",
        [0x2017] = "UnknownVendorCode",
        [0x2018] = "CaptureAlreadyTerminated",
        [0x2019] = "DeviceBusy",
        [0x201A] = "InvalidParentObject",
        [0x201B] = "InvalidDevicePropFormat",
        [0x201C] = "InvalidDevicePropValue",
        [0xA001] = "InvalidObjectPropCode",
        [0xA002] = "InvalidObjectPropFormat",
        [0xA003] = "InvalidObjectPropValue",
        [0xA004] = "InvalidObjectReference",
        [0xA005] = "GroupNotSupported"
}

local event_codes = {
    [0x4000] = "Undefined",
    [0x4001] = "CancelTransaction",
    [0x4002] = "ObjectAdded",
    [0x4003] = "ObjectRemoved",
    [0x4004] = "StoreAdded",
    [0x4005] = "StoreRemoved",
    [0x4006] = "DevicePropChanged",
    [0x4007] = "ObjectInfoChanged",
    [0x4008] = "DeviceInfoChanged",
    [0x4009] = "RequestObjectTransfer",
    [0x400A] = "StoreFull",
    [0x400B] = "DeviceReset",
    [0x400C] = "StorageInfoChanged",
    [0x400D] = "CaptureComplete",
    [0x400E] = "UnreportedStatus",
    [0x400F] = "ObjectRemovedFromStorage",
    [0x4010] = "StoreAddedToStorage",
    [0x4011] = "DevicePropDescChanged",
    [0x4012] = "ObjectReferencesChanged",
    [0x4013] = "ObjectPropValueChanged",
    [0x4014] = "ObjectPropDescChanged",
    [0x4015] = "ObjectReferencesAdded",
    [0x4016] = "ObjectReferencesRemoved",
    [0xC801] = "PtpipSessionOpened",
    [0xC802] = "PtpipSessionClosed",
    [0xC803] = "PtpipSessionChanged",
    [0xC804] = "PtpipEvent",
}

local container_types = {
        [0x0000] = "Undefined",
        [0x0001] = "Command",
        [0x0002] = "Data",
        [0x0003] = "Response",
        [0x0004] = "Event",
        [0xFFFF] = "Vendor"
}

usb_mtp_protocol = Proto("USB_MTP", "USB MTP")

local length = ProtoField.uint32("usb_mtp.header_length", "Header Length", base.HEX)
local type = ProtoField.uint16("usb_mtp.header_type", "Command Type", base.HEX)
local code = ProtoField.uint16("usb_mtp.header_code", "Command Code", base.HEX)
local transID = ProtoField.uint32("usb_mtp.header_transID", "Transaction ID", base.HEX)
local parameters = {}

for i = 1,4 do
        parameters[i] = ProtoField.uint32("usb_mtp.parameter"..i, "Parameter"..i, base.HEX)
end
local data = ProtoField.bytes("usb_mtp.data", "Data", base.SPACE)


usb_mtp_protocol.fields = {
        length, type, code, transID, parameters[1], parameters[2],parameters[3],parameters[4],parameters[5],
        data
}

function usb_mtp_protocol.dissector(buffer, pinfo, tree)
        local buffer_length = buffer:len()

        if buffer_length == 0 then return end

        pinfo.cols.protocol = usb_mtp_protocol.name
        local subtree_name = function()
                if buffer_length <= 32 then
                        return "Header"
                else
                        return "Data"
                end
        end
        local subtree = tree:add(usb_mtp_protocol, buffer, subtree_name())

        local code2text = function(t, c)
                if t == "Undefined" then
                        return "Undefined"
                elseif t == "Command" then
                        return operations[c]
                elseif t == "Data" then
                        return "Data"
                elseif t == "Response" then
                        return response_codes[c]
                elseif t == "Event" then
                        return event_codes[c]
                end
        end

        if buffer_length <= 32 then
                local container_type = container_types[buffer(4,2):le_uint()]
                local code_text = code2text(container_type, buffer(6,2):le_uint())
                if code_text == nil then
                        code_text = buffer(6,2):le_uint()--" Unknown Code"
                end
                subtree:add_le(length,     buffer(0, 4))
                subtree:add_le(type,       buffer(4, 2)):append_text(" " .. container_type)
                subtree:add_le(code,       buffer(6, 2)):append_text(" " .. code_text)
                subtree:add_le(transID,    buffer(8, 4))
                local j = 1
                for i = 12,buffer_length - 1,4 do
                        local bit_offset = 12 + (j - 1)* 4
                        subtree:add_le(parameters[j],      buffer(bit_offset,  4))
                        j = j + 1;
                end
        else
                subtree:add_le(data, buffer(0,buffer_length))
        end
end

DissectorTable.get("usb.bulk"):add(0x06, usb_mtp_protocol)
