// Copyright (c) 2020 The Orbit Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "CallstackDataView.h"
#include "ClientData/CallstackTypes.h"
#include "ClientData/PostProcessedSamplingData.h"
#include "ClientModel/SamplingDataPostProcessor.h"
#include "DataViews/DataView.h"
#include "absl/container/flat_hash_set.h"
#include "capture_data.pb.h"

class OrbitApp;
class SamplingReport;

class SamplingReportDataView : public orbit_data_views::DataView {
 public:
  explicit SamplingReportDataView(OrbitApp* app);

  const std::vector<Column>& GetColumns() override;
  int GetDefaultSortingColumn() override { return kColumnInclusive; }
  std::vector<std::string> GetContextMenu(int clicked_index,
                                          const std::vector<int>& selected_indices) override;
  std::string GetValue(int row, int column) override;
  const std::string& GetName() { return name_; }

  void OnContextMenu(const std::string& action, int menu_index,
                     const std::vector<int>& item_indices) override;
  void OnSelect(const std::vector<int>& indices) override;
  void OnRefresh(const std::vector<int>& visible_selected_indices,
                 const RefreshMode& mode) override;

  void LinkDataView(orbit_data_views::DataView* data_view) override;
  void SetSamplingReport(class SamplingReport* sampling_report) {
    sampling_report_ = sampling_report;
  }
  void SetSampledFunctions(const std::vector<orbit_client_data::SampledFunction>& functions);
  void SetThreadID(orbit_client_data::ThreadID tid);
  orbit_client_data::ThreadID GetThreadID() const { return tid_; }

 protected:
  void DoSort() override;
  void DoFilter() override;
  const orbit_client_data::SampledFunction& GetSampledFunction(unsigned int row) const;
  orbit_client_data::SampledFunction& GetSampledFunction(unsigned int row);
  absl::flat_hash_set<const orbit_client_protos::FunctionInfo*> GetFunctionsFromIndices(
      const std::vector<int>& indices);
  [[nodiscard]] absl::flat_hash_set<std::pair<std::string, std::string>>
  GetModulePathsAndBuildIdsFromIndices(const std::vector<int>& indices) const;

 private:
  void UpdateSelectedIndicesAndFunctionIds(const std::vector<int>& selected_indices);
  void RestoreSelectedIndicesAfterFunctionsChanged();
  // The callstack view will be updated according to the visible selected addresses and thread id.
  void UpdateVisibleSelectedAddressesAndTid(const std::vector<int>& visible_selected_indices);

  std::vector<orbit_client_data::SampledFunction> functions_;
  // We need to keep user's selected function ids such that if functions_ changes, the
  // selected_indices_ can be updated according to the selected function ids.
  absl::flat_hash_set<uint64_t> selected_function_ids_;
  orbit_client_data::ThreadID tid_ = -1;
  std::string name_;
  CallstackDataView* callstack_data_view_;
  SamplingReport* sampling_report_ = nullptr;

  enum ColumnIndex {
    kColumnSelected,
    kColumnFunctionName,
    kColumnExclusive,
    kColumnInclusive,
    kColumnModuleName,
    kColumnAddress,
    kColumnUnwindErrors,
    kNumColumns
  };

  static const std::string kMenuActionSelect;
  static const std::string kMenuActionUnselect;
  static const std::string kMenuActionLoadSymbols;
  static const std::string kMenuActionDisassembly;
  static const std::string kMenuActionSourceCode;

  // TODO(b/185090791): This is temporary and will be removed once this data view has been ported
  // and move to orbit_data_views.
  OrbitApp* app_ = nullptr;
};
