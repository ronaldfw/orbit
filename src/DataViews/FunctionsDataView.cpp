// Copyright (c) 2021 The Orbit Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "DataViews/FunctionsDataView.h"

#include <absl/flags/declare.h>
#include <absl/flags/flag.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_split.h>
#include <stddef.h>

#include <algorithm>
#include <cstdint>
#include <functional>

#include "ClientData/FunctionUtils.h"
#include "ClientData/ModuleData.h"
#include "ClientData/ProcessData.h"
#include "ClientModel/CaptureData.h"
#include "CompareAscendingOrDescending.h"
#include "DataViews/AppInterface.h"
#include "DataViews/DataViewType.h"
#include "OrbitBase/Append.h"
#include "OrbitBase/Logging.h"

#ifdef _WIN32
#include "oqpi.hpp"

#define OQPI_USE_DEFAULT
#endif

using orbit_client_data::ModuleData;
using orbit_client_data::ProcessData;
using orbit_client_model::CaptureData;
using orbit_client_protos::FunctionInfo;

namespace orbit_data_views {

FunctionsDataView::FunctionsDataView(AppInterface* app) : DataView(DataViewType::kFunctions, app) {}

const std::string FunctionsDataView::kUnselectedFunctionString = "";
const std::string FunctionsDataView::kSelectedFunctionString = "✓";
const std::string FunctionsDataView::kFrameTrackString = "F";

const std::vector<DataView::Column>& FunctionsDataView::GetColumns() {
  static const std::vector<Column> columns = [] {
    std::vector<Column> columns;
    columns.resize(kNumColumns);
    columns[kColumnSelected] = {"Hooked", .0f, SortingOrder::kDescending};
    columns[kColumnName] = {"Function", .65f, SortingOrder::kAscending};
    columns[kColumnSize] = {"Size", .0f, SortingOrder::kAscending};
    columns[kColumnModule] = {"Module", .0f, SortingOrder::kAscending};
    columns[kColumnAddressInModule] = {"Address in module", .0f, SortingOrder::kAscending};
    return columns;
  }();
  return columns;
}

bool FunctionsDataView::ShouldShowSelectedFunctionIcon(AppInterface* app,
                                                       const FunctionInfo& function) {
  return app->IsFunctionSelected(function);
}

bool FunctionsDataView::ShouldShowFrameTrackIcon(AppInterface* app, const FunctionInfo& function) {
  if (app->IsFrameTrackEnabled(function)) {
    return true;
  }

  if (!app->HasCaptureData()) {
    return false;
  }

  const CaptureData& capture_data = app->GetCaptureData();
  std::optional<uint64_t> instrumented_function_id =
      capture_data.FindInstrumentedFunctionIdSlow(function);

  return instrumented_function_id &&
         app->HasFrameTrackInCaptureData(instrumented_function_id.value());
}

std::string FunctionsDataView::BuildSelectedColumnsString(AppInterface* app,
                                                          const FunctionInfo& function) {
  std::string result = kUnselectedFunctionString;
  if (ShouldShowSelectedFunctionIcon(app, function)) {
    absl::StrAppend(&result, kSelectedFunctionString);
    if (ShouldShowFrameTrackIcon(app, function)) {
      absl::StrAppend(&result, " ", kFrameTrackString);
    }
  } else if (ShouldShowFrameTrackIcon(app, function)) {
    absl::StrAppend(&result, kFrameTrackString);
  }
  return result;
}

std::string FunctionsDataView::GetValue(int row, int column) {
  if (row >= static_cast<int>(GetNumElements())) {
    return "";
  }

  const FunctionInfo& function = *GetFunction(row);

  switch (column) {
    case kColumnSelected:
      return BuildSelectedColumnsString(app_, function);
    case kColumnName:
      return orbit_client_data::function_utils::GetDisplayName(function);
    case kColumnSize:
      return absl::StrFormat("%lu", function.size());
    case kColumnModule:
      return orbit_client_data::function_utils::GetLoadedModuleName(function);
    case kColumnAddressInModule:
      return absl::StrFormat("%#x", function.address());
    default:
      return "";
  }
}

#define ORBIT_FUNC_SORT(Member)                                                                   \
  [&](int a, int b) {                                                                             \
    return CompareAscendingOrDescending(functions_[a]->Member, functions_[b]->Member, ascending); \
  }

#define ORBIT_CUSTOM_FUNC_SORT(Func)                                                            \
  [&](int a, int b) {                                                                           \
    return CompareAscendingOrDescending(Func(*functions_[a]), Func(*functions_[b]), ascending); \
  }

void FunctionsDataView::DoSort() {
  // TODO(antonrohr): This sorting function can take a lot of time when a large
  // number of functions is used (several seconds). This function is currently
  // executed on the main thread and therefore freezes the UI and interrupts the
  // ssh watchdog signals that are sent to the service. Therefore this should
  // not be called on the main thread and as soon as this is done the watchdog
  // timeout should be rolled back from 25 seconds to 10 seconds in
  // OrbitService.h
  bool ascending = sorting_orders_[sorting_column_] == SortingOrder::kAscending;
  std::function<bool(int a, int b)> sorter = nullptr;

  switch (sorting_column_) {
    case kColumnSelected:
      sorter = ORBIT_CUSTOM_FUNC_SORT(app_->IsFunctionSelected);
      break;
    case kColumnName:
      sorter = ORBIT_CUSTOM_FUNC_SORT(orbit_client_data::function_utils::GetDisplayName);
      break;
    case kColumnSize:
      sorter = ORBIT_FUNC_SORT(size());
      break;
    case kColumnModule:
      sorter = ORBIT_CUSTOM_FUNC_SORT(orbit_client_data::function_utils::GetLoadedModuleName);
      break;
    case kColumnAddressInModule:
      sorter = ORBIT_FUNC_SORT(address());
      break;
    default:
      break;
  }

  if (sorter) {
    std::stable_sort(indices_.begin(), indices_.end(), sorter);
  }
}

const std::string FunctionsDataView::kMenuActionSelect = "Hook";
const std::string FunctionsDataView::kMenuActionUnselect = "Unhook";
const std::string FunctionsDataView::kMenuActionEnableFrameTrack = "Enable frame track(s)";
const std::string FunctionsDataView::kMenuActionDisableFrameTrack = "Disable frame track(s)";
const std::string FunctionsDataView::kMenuActionDisassembly = "Go to Disassembly";
const std::string FunctionsDataView::kMenuActionSourceCode = "Go to Source code";

std::vector<std::string> FunctionsDataView::GetContextMenu(
    int clicked_index, const std::vector<int>& selected_indices) {
  bool enable_select = false;
  bool enable_unselect = false;
  bool enable_enable_frame_track = false;
  bool enable_disable_frame_track = false;

  for (int index : selected_indices) {
    const FunctionInfo& function = *GetFunction(index);
    enable_select |= !app_->IsFunctionSelected(function);
    enable_unselect |= app_->IsFunctionSelected(function);
    enable_enable_frame_track |= !app_->IsFrameTrackEnabled(function);
    enable_disable_frame_track |= app_->IsFrameTrackEnabled(function);
  }

  std::vector<std::string> menu;
  if (enable_select) menu.emplace_back(kMenuActionSelect);
  if (enable_unselect) menu.emplace_back(kMenuActionUnselect);
  if (enable_enable_frame_track) menu.emplace_back(kMenuActionEnableFrameTrack);
  if (enable_disable_frame_track) menu.emplace_back(kMenuActionDisableFrameTrack);
  menu.emplace_back(kMenuActionDisassembly);
  menu.emplace_back(kMenuActionSourceCode);
  orbit_base::Append(menu, DataView::GetContextMenu(clicked_index, selected_indices));
  return menu;
}

void FunctionsDataView::OnContextMenu(const std::string& action, int menu_index,
                                      const std::vector<int>& item_indices) {
  if (action == kMenuActionSelect) {
    for (int i : item_indices) {
      app_->SelectFunction(*GetFunction(i));
    }
  } else if (action == kMenuActionUnselect) {
    for (int i : item_indices) {
      app_->DeselectFunction(*GetFunction(i));
      // Unhooking a function implies disabling (and removing) the frame
      // track for this function. While it would be possible to keep the
      // current frame track in the capture data, this would lead to a
      // somewhat inconsistent state where the frame track for this function
      // is enabled for the current capture but disabled for the next one.
      app_->DisableFrameTrack(*GetFunction(i));
      app_->RemoveFrameTrack(*GetFunction(i));
    }
  } else if (action == kMenuActionEnableFrameTrack) {
    for (int i : item_indices) {
      const FunctionInfo& function = *GetFunction(i);
      // Functions used as frame tracks must be hooked (selected), otherwise the
      // data to produce the frame track will not be captured.
      app_->SelectFunction(function);
      app_->EnableFrameTrack(function);
      app_->AddFrameTrack(function);
    }
  } else if (action == kMenuActionDisableFrameTrack) {
    for (int i : item_indices) {
      // When we remove a frame track, we do not unhook (deselect) the function as
      // it may have been selected manually (not as part of adding a frame track).
      // However, disable the frame track, so it is not recreated on the next capture.
      app_->DisableFrameTrack(*GetFunction(i));
      app_->RemoveFrameTrack(*GetFunction(i));
    }
  } else if (action == kMenuActionDisassembly) {
    for (int i : item_indices) {
      app_->Disassemble(app_->GetTargetProcess()->pid(), *GetFunction(i));
    }
  } else if (action == kMenuActionSourceCode) {
    for (int i : item_indices) {
      app_->ShowSourceCode(*GetFunction(i));
    }
  } else {
    DataView::OnContextMenu(action, menu_index, item_indices);
  }
}

void FunctionsDataView::DoFilter() {
  m_FilterTokens = absl::StrSplit(absl::AsciiStrToLower(filter_), ' ');

#ifdef WIN32
  ParallelFilter();
#else
  // TODO: port parallel filtering
  std::vector<uint64_t> indices;
  const std::vector<const FunctionInfo*>& functions(functions_);
  for (size_t i = 0; i < functions.size(); ++i) {
    const FunctionInfo* function = functions[i];
    std::string name =
        absl::AsciiStrToLower(orbit_client_data::function_utils::GetDisplayName(*function)) +
        orbit_client_data::function_utils::GetLoadedModuleName(*function);

    bool match = true;

    for (std::string& filter_token : m_FilterTokens) {
      if (name.find(filter_token) == std::string::npos) {
        match = false;
        break;
      }
    }

    if (match) {
      indices.push_back(i);
    }
  }

  indices_ = std::move(indices);
#endif
}

void FunctionsDataView::ParallelFilter() {
#ifdef _WIN32
  const std::vector<const FunctionInfo*>& functions(functions_);
  const auto prio = oqpi::task_priority::normal;
  auto numWorkers = oqpi::default_helpers::scheduler().workersCount(prio);
  // int numWorkers = oqpi::thread::hardware_concurrency();
  std::vector<std::vector<int>> indicesArray;
  indicesArray.resize(numWorkers);

  oqpi::default_helpers::parallel_for(
      "FunctionsDataViewParallelFor", functions.size(),
      [&](int32_t a_BlockIndex, int32_t a_ElementIndex) {
        std::vector<int>& result = indicesArray[a_BlockIndex];
        const std::string& name = absl::AsciiStrToLower(
            orbit_client_data::function_utils::GetDisplayName(*functions[a_ElementIndex]));
        const std::string& module =
            orbit_client_data::function_utils::GetLoadedModuleName(*functions[a_ElementIndex]);

        for (std::string& filterToken : m_FilterTokens) {
          if (name.find(filterToken) == std::string::npos &&
              module.find(filterToken) == std::string::npos) {
            return;
          }
        }

        result.push_back(a_ElementIndex);
      });

  std::set<int> indicesSet;
  for (std::vector<int>& results : indicesArray) {
    for (int index : results) {
      indicesSet.insert(index);
    }
  }

  indices_.clear();
  for (int i : indicesSet) {
    indices_.push_back(i);
  }
#endif
}

void FunctionsDataView::AddFunctions(
    std::vector<const orbit_client_protos::FunctionInfo*> functions) {
  functions_.insert(functions_.end(), functions.begin(), functions.end());
  indices_.resize(functions_.size());
  for (size_t i = 0; i < indices_.size(); ++i) {
    indices_[i] = i;
  }
  OnDataChanged();
}

void FunctionsDataView::ClearFunctions() {
  functions_.clear();
  OnDataChanged();
}

}  // namespace orbit_data_views