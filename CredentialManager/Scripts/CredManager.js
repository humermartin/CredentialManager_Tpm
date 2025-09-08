$(document).ready(function ()
{
    hideCredentialFields();

    if ($("#fldCredTypes  :selected").val() !== "") {
        UpdateCredentialType($("#fldCredTypes  :selected").val());
    }

    
    $("#chkServiceCall")
        .bootstrapSwitch({
            onSwitchChange: function (e, state) {
                $("#ServiceCallSelected").val(state);
                SetCredStoreServiceCall(state);
            }
        });

    $(function () {
        $("#dialog").dialog();
    });

    $(".removeAdUser")
        .hover(function () {
            $(this).css("cursor", "pointer");
        })
        .on("click", function () {
            var adUser = $(this).attr('id');
            var adUserName = $(this).parent().attr('id');

            var removeDialog = $(document.createElement('div'));
            removeDialog.dialog({
                autoOpen: true,
                title: 'Delete Message for User:' + adUserName,
                modal: true,
                width: 350,
                height: 300,
                buttons: {
                    Yes: function () {
                        RemoveAdUser(adUser);
                        $(this).dialog("close");
                    },
                    No: function() {
                        $(this).dialog("close");
                    }
                },
                show: {
                    effect: "bounce",
                    duration: 1500
                },
                hide: {
                    effect: "fade",
                    duration: 1000
                }

            }).text("Are you sure you want to remove the user and his own credentials ? Assigned credentials from this user will be not deleted because there are used by other users.");
        });
        $(".selector").dialog({
            closeOnEscape: false
    });


    $(".removeUserCredential")
        .hover(function() {
            $(this).css("cursor", "pointer");
    });
        

    $(".loadAssignement")
        .hover(function () {
            $(this).css("cursor", "pointer");
        })
        .on("click", function () {
            LoadPrincipalGridData(0, 10, $(this).attr('id'));
            $('#modalPrincipals').modal('show');
           
           
    });

    $(".changeAdUserRole").on("change", function () {
        UpdateAdUserRole($(this).attr('id'), $(this).val());
    });

    $(".checkAdUser").on("click", function () {
        UpdateAdUserActivation($(this).attr('id'), $(this).is(":checked"));
    });

    $("#idCredRoles").on("change", function () {
        if ($("#idCredRoles").val().length !== 0 && $("#adUserName").val().length !== 0) {
            $("#btnRegisterAdUser").attr('disabled', false);
        } else {
            $("#btnRegisterAdUser").attr('disabled', true);
        }
    });
});

function UpdateCredentialType(credType) {
    var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
    $.ajax({
        type: "POST",
        url: "/Home/GetCredentialTypeName",
        data: {
            __RequestVerificationToken: antiForgeryToken,
            typeId: credType
        },
        dataType: "json",
        success: function (result) {
            if (result !== null && result !== undefined) {
                hideCredentialFields();

                if (result.CredentialTypeName === "") {
                    return;
                }

                var jCredTypeName = JSON.parse(result.CredentialTypeName);
                
                switch (jCredTypeName) {
                    case "basic_auth":
                        setStandardLogin();
                        break;
                    case "cim":
                        setStandardLogin();
                        break;
                    case "mssql":
                        setStandardLogin();
                        break;
                    case "snmp":
                        $('#fldPassword').show();
                        $('#fldConfirmPassword').show();
                        break;
                    case "snmpv3":
                        $('#fldPassword').hide();
                        $('#fldConfirmPassword').hide();
                        $('#fldUsername').show();
                        $('#ddAuthProtocol').show();
                        $('#ddPrivacyProtocol').show();
                        break;
                    case "ssh":
                        setStandardLogin();
                        break;
                    case "ssh_password":
                        setStandardLogin();
                        break;
                    case "ssh_private_key":
                        $('#fldUsername').show();
                        $('#fldPassword').show();
                        $('#fldConfirmPassword').show();
                        $('#fldsshpassphrase').show();
                        $('#fldsshprivatekey').show();
                        break;
                    case "u_cmdb_ci_ms_scvmm":
                        setStandardLogin();
                        break;
                    case "vmware":
                        setStandardLogin();
                        break;
                    case "windows":
                        setStandardLogin();
                        break;
                default:
                    
                }

            }
        },
        failure: function (xhr, status) {

        }
    });
}

function hideCredentialFields() {
    $('#ddAuthProtocol').hide();
    $('#ddPrivacyProtocol').hide();
    $('#fldsshpassphrase').hide();
    $('#fldsshprivatekey').hide();
    $('#fldUsername').hide();
    $('#fldPassword').hide();
    $('#fldConfirmPassword').hide();
}

function setStandardLogin() {
    $('#fldUsername').show();
    $('#fldPassword').show();
    $('#fldConfirmPassword').show();
}

function SearchAdUser() {
    
    if ($('#adUserName').val() !== undefined) {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            url: "/Home/ValidateAdUser",
            data: {
                __RequestVerificationToken: antiForgeryToken,
                adUser: $('#adUserName').val()
            },
            dataType: "json",
            success: function (response) {
                if (response.ValidateUIDResult === true) {
                    $("#idSamAccountname").val(response.PrincipalModel.SamAccountName);
                    $("#idFirstName").val(response.PrincipalModel.FirstName);
                    $("#idLastName").val(response.PrincipalModel.LastName);

                    if ($("#idSamAccountname").val().length !== 0 && $("#idCredRoles").val().length !== 0) {
                        $("#btnRegisterAdUser").attr('disabled', false);
                    }

                } else {
                    $("#validateAdUserMessage").text(response.Message);
                }
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }
    
}

//add adUser from credential-manager
function AddAdUser() {
    
    if ($('#adUserName').val() !== "" && $("#idCredRoles").val() !== "") {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            url: "/Home/RegisterPrincipals",
            data: {
                __RequestVerificationToken: antiForgeryToken,
                adUser: $('#adUserName').val(),
                credRole: $('#idCredRoles').val()
            },
            dataType: "json",
            success: function (response) {
                if (response.AddAdUserResult === false) {
                    $("#validateAdUserMessage").text(response.Message);
                } else {
                    window.location.href = "/Home/ManagePrincipals/";
                }
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }

}

//remove adUser from credential-manager
function RemoveAdUser(principalId) {

    if (principalId !== "") {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            url: "/Manage/RemoveAdUserAccount",
            data: { __RequestVerificationToken: antiForgeryToken, principalId: principalId },
            dataType: "json",
            success: function (response) {
                if (response.RemoveAdUserResult === false) {
                    $("#validateAdUserListMessage").text(response.Message);
                }
                window.location.href = response.RedirectUrl;
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }

}

//upade adUser activation
function UpdateAdUserActivation(principalId, active) {
    
    if (principalId !== "" && active !== null) {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            url: "/Manage/UpdateAdUserActivation",
            data: { __RequestVerificationToken: antiForgeryToken, principalId: principalId, active: active },
            dataType: "json",
            success: function (response) {
                if (response.UpdateActivationResult === false) {
                    $('#validateAdUserListMessage').addClass('text-danger').removeClass('text-success');
                } else {
                    $('#validateAdUserListMessage').addClass('text-success').removeClass('text-danger');
                }
                $("#validateAdUserListMessage").text(response.Message);
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }

}

//update adUser Roles
function UpdateAdUserRole(principalId, roleId) {
    if (principalId !== "" && roleId !== "") {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            beforeSend: function (request) {
                request.setRequestHeader("X-Content-Type-Options", "nosniff");
            },
            url: "/Manage/UpdateAdUserRole",
            data: { __RequestVerificationToken: antiForgeryToken, principalId: principalId, roleId: roleId },
            success: function (response) {
                if (response.UpdateAdUserRoleResult === false) {
                    $('#validateAdUserListMessage').addClass('text-danger').removeClass('text-success');
                } else {
                    $('#validateAdUserListMessage').addClass('text-success').removeClass('text-danger');
                }
                $("#validateAdUserListMessage").text(response.Message);
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }
}

//remove credential from store
function RemoveAdUserCredential(object) {
    var storeId = object.attr('id');

    if (storeId !== "") {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            type: "POST",
            url: "/Manage/RemoveCredential",
            data: { __RequestVerificationToken: antiForgeryToken, storeId: storeId },
            dataType: "json",
            traditional: true,
            success: function (response) {
                if (response.RemoveCredentialResult === true) {
                    window.location.href = "/Home/ManageCredential/";
                }
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }
}

function SetCredStoreServiceCall(state) {

    var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
    $.ajax({
        type: "POST",
        url: "/Manage/SetCredStoreServiceCall",
        data: { __RequestVerificationToken: antiForgeryToken, serviceCallStatus: state },
        dataType: "json",
        traditional: true,
        success: function (response) {
            
        },
        failure: function (xhr, status) {
            alertify.error(status + " - " + xhr.responseText);
        }
    });
}