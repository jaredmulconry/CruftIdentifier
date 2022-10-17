#pragma once
#include "PatternLoader.h"
#include <string_view>

void CheckAndReportPatterns(std::string_view basePath, const std::vector<MatchSet>& badSets);

void FixCurrentDirectory(std::string_view correctPath);