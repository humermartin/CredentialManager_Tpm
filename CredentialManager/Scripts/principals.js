$(document).ready(function () {

    //Load finished clients page
    principalSelection = [];

    $("#idCloseAndSaveDialog").on("click",
        function() {
            $('#modalPrincipals').modal('hide');
        });
});

function LoadPrincipalGridData(skip, take, storeId) {
    $("#principalGrid").css("display", "block");
    $("#modStoreId").val(storeId);
    var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();

    $("#principalGrid").kendoGrid({
        groupable: true,
        editable: false,
        sortable: true,
        filterable: true,
        resizable: true,
        scrollable: true,
        filterMenuInit: filterMenuInit,
        pageable: {
            refresh: true,
            pageSizes: [5, 10, 20, 50, 100],
            previousNext: true,
            buttonCount: 30,
            messages: {
                display: "{0} - {1} of {2} AD Users",
                itemsPerPage: "User pro Seite",
                empty: "Keine Daten",
                allPages: "Alle"
            }
        },
        dataSource:
        {
            transport: {
                read: {
                    url: "/Manage/LoadPrincipals",
                    type: "POST",
                    dataType: "json",
                    data: {
                        storeId: storeId,
                        skip: skip,
                        take: take,
                        filter: null
                    }
                },
                parameterMap: function (data, type) {
                    if (type === "read") {

                        var skip = (data.page * data.pageSize) - data.pageSize;

                        if (data.filter !== 0 && data.filter !== null) {
                            return {
                                __RequestVerificationToken: antiForgeryToken,
                                storeId: storeId,
                                skip: skip,
                                take: data.pageSize,
                                filter: JSON.stringify(data.filter.filters)
                            }
                        }
                        return {
                            __RequestVerificationToken: antiForgeryToken,
                            storeId: storeId,
                            skip: skip,
                            take: data.pageSize,
                            filter: null
                        }
                    }
                }
            },
            schema: {
                data: function (result) {
                    $("#modalPrincipalTitelHeader").text(result.ModelDescription);
                    return result.Principals;
                },
                total: function (result) {
                    return result.PrincipalsTotalCount;
                },
                model: {
                    fields: {
                        UserName: { type: "text", editable: false }
                    }
                }
            },
            serverPaging: true,
            serverFiltering: true,
            serverSorting: true,
            pageSize: 10
        },
        columns: [
            {
                attributes: { style: "text-align:center" },
                template: '<input type="checkbox" #= IsAssignedToStoreId ? checked="checked":"" # class="chkbxFinishedClients" />',
                width: 20,
                editable: true
            }, {
                field: "UserName",
                title: "UserName",
                filterable: { extra: false },
                width: 90
            }
        ]
    });

    var principalGrid = $("#principalGrid").data("kendoGrid");
    principalGrid.table.on("click", ".chkbxFinishedClients", UpdatePrincipals);
}

function UpdatePrincipals() {
    kendo.ui.progress($("#principalGrid"), true);
    var changedSelection = this.checked, row = $(this).closest("tr"),
        grid = $("#principalGrid").data("kendoGrid"),
        principalItem = grid.dataItem(row);

    if (principalItem !== null && principalItem !== undefined) {

        if (this.checked) {
            //add if id is not in list  
            if (principalSelection.indexOf(principalItem.Id) < 0) {
                UpdateCredentialAssignement($("#modStoreId").val(), principalItem.Id, true);
                kendo.ui.progress($("#principalGrid"), false);
            }
        } else {
            //remove id if it is in list
            UpdateCredentialAssignement($("#modStoreId").val(), principalItem.Id, false);
            kendo.ui.progress($("#principalGrid"), false);
            return principalItem.Id;
        }
    }
}

function filterMenuInit(e) {
    e.container.on("click", "[type='reset']", function () {
        var dataSource = $("#principalClientGrid").data("kendoGrid").dataSource;
        if (dataSource.filter() !== null) {
            dataSource.filter([]);
        }
    });
}

//update adUser credential assignement
function UpdateCredentialAssignement(storeId, userId, checkValue) {
    if (storeId !== "" && userId !== 0) {
        var antiForgeryToken = $("input[name=__RequestVerificationToken]").val();
        $.ajax({
            async: false,
            type: "POST",
            url: "/Manage/UpdateCredentialAssignement",
            data: {
                __RequestVerificationToken: antiForgeryToken,
                storeId: storeId,
                userId: userId,
                checkValue: checkValue
            },
            dataType: "json",
            traditional: true,
            success: function (response) {
                if (response.UpdateAdUserRoleResult === false) {
                    $('#validateManageCredential').addClass('text-danger').removeClass('text-success');
                } else {
                    $('#validateManageCredential').addClass('text-success').removeClass('text-danger');
                }
                $("#validateManageCredential").text(response.Message);
            },
            failure: function (xhr, status) {
                alertify.error(status + " - " + xhr.responseText);
            }
        });
    }
}

