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

// AccessService is a mock of AccessService
type AccessServiceMock struct {
	StartAccessUpdaterFunc      func(context.Context) <-chan error
	RefreshAccessTokenCacheFunc func(ctx context.Context) <-chan error
	GetAccessProviderFunc       func() AccessProvider
	TokenCacheLenFunc           func() int
	TokenCacheSizeFunc          func() int64
}

// StartAccessUpdater is a mock implementation of AccessService.StartAccessUpdater
func (asm *AccessServiceMock) StartAccessUpdater(ctx context.Context) <-chan error {
	return asm.StartAccessUpdaterFunc(ctx)
}

// RefreshAccessTokenCache is a mock implementation of AccessService.RefreshAccessTokenCache
func (asm *AccessServiceMock) RefreshAccessTokenCache(ctx context.Context) <-chan error {
	return asm.RefreshAccessTokenCacheFunc(ctx)
}

// GetAccessProvider is a mock implementation of AccessService.GetAccessProvider
func (asm *AccessServiceMock) GetAccessProvider() AccessProvider {
	return asm.GetAccessProviderFunc()
}

func (asm *AccessServiceMock) TokenCacheLen() int {
	return asm.TokenCacheLenFunc()
}

func (asm *AccessServiceMock) TokenCacheSize() int64 {
	return asm.TokenCacheSizeFunc()
}
