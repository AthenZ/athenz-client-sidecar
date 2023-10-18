// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import "context"

// RoleService is a mock of RoleService
type RoleServiceMock struct {
	StartRoleUpdaterFunc      func(context.Context) <-chan error
	RefreshRoleTokenCacheFunc func(ctx context.Context) <-chan error
	GetRoleProviderFunc       func() RoleProvider
}

// StartRoleUpdater is a mock implementation of RoleService.StartRoleUpdater
func (asm *RoleServiceMock) StartRoleUpdater(ctx context.Context) <-chan error {
	return asm.StartRoleUpdaterFunc(ctx)
}

// RefreshRoleTokenCache is a mock implementation of RoleService.RefreshRoleTokenCache
func (asm *RoleServiceMock) RefreshRoleTokenCache(ctx context.Context) <-chan error {
	return asm.RefreshRoleTokenCacheFunc(ctx)
}

// GetRoleProvider is a mock implementation of RoleService.GetRoleProvider
func (asm *RoleServiceMock) GetRoleProvider() RoleProvider {
	return asm.GetRoleProviderFunc()
}
