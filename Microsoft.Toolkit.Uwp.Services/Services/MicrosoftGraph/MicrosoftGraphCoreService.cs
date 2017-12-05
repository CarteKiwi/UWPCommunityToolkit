﻿// ******************************************************************
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THE CODE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE CODE OR THE USE OR OTHER DEALINGS IN THE CODE.
// ******************************************************************

using System;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Graph;
using static Microsoft.Toolkit.Uwp.Services.MicrosoftGraph.MicrosoftGraphEnums;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Windows.Security.Authentication.Web;

namespace Microsoft.Toolkit.Uwp.Services.MicrosoftGraph
{
    /// <summary>
    ///  Class for connecting to Office 365 Microsoft Graph
    /// </summary>
    public partial class MicrosoftGraphService
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MicrosoftGraphService"/> class.
        /// </summary>
        public MicrosoftGraphService()
        {
        }

        /// <summary>
        /// Private singleton field.
        /// </summary>
        private static MicrosoftGraphService _instance;

        /// <summary>
        /// Store an instance of the MicrosoftGraphAuthenticationHelper class
        /// </summary>
        private MicrosoftGraphAuthenticationHelper _authentication;

        /// <summary>
        /// Store a reference to an instance of the underlying data provider.
        /// </summary>
        private GraphServiceClient _graphProvider;

        /// <summary>
        /// Gets public singleton property.
        /// </summary>
        public static MicrosoftGraphService Instance => _instance ?? (_instance = new MicrosoftGraphService());

        /// <summary>
        /// Field for tracking initialization status.
        /// </summary>
        private bool _isInitialized;

        /// <summary>
        /// Field for tracking if the user is connected.
        /// </summary>
        private bool _isConnected;

        /// <summary>
        /// Field to store Azure AD Application clientid
        /// </summary>
        private string _appClientId;

        /// <summary>
        /// Field to store the services to initialize
        /// </summary>
        private ServicesToInitialize _servicesToInitialize;

        /// <summary>
        /// Field to store the model of authentication
        /// V1 Only for Work or Scholar account
        /// V2 for MSA and Work or Scholar account
        /// </summary>
        private AuthenticationModel _authenticationModel = AuthenticationModel.V1;

        private DeviceCodeResult _deviceCode;

        /// <summary>
        /// Gets the code to authenticate from a remote device
        /// </summary>
        public string UserCode
        {
            get { return _deviceCode.UserCode; }
        }

        /// <summary>
        /// Fields to store a MicrosoftGraphServiceMessages instance
        /// </summary>
        private MicrosoftGraphUserService _user;

        /// <summary>
        /// Gets a reference to an instance of the MicrosoftGraphUserService class
        /// </summary>
        public MicrosoftGraphUserService User
        {
            get { return _user; }
        }

        /// <summary>
        /// Initialize Microsoft Graph.
        /// </summary>
        /// <param name='appClientId'>Azure AD's App client id</param>
        /// <param name="authenticationModel">V1 or V2</param>
        /// <param name="servicesToInitialize">A combination of value to instanciate different services</param>
        /// <returns>Success or failure.</returns>
        public bool Initialize(string appClientId, AuthenticationModel authenticationModel = AuthenticationModel.V1, ServicesToInitialize servicesToInitialize = ServicesToInitialize.Message | ServicesToInitialize.UserProfile | ServicesToInitialize.Event)
        {
            if (string.IsNullOrEmpty(appClientId))
            {
                throw new ArgumentNullException(nameof(appClientId));
            }

            _appClientId = appClientId;
            _authenticationModel = authenticationModel;
            _graphProvider = CreateGraphClientProvider(appClientId, authenticationModel);
            _servicesToInitialize = servicesToInitialize;
            _isInitialized = true;
            return true;
        }

        /// <summary>
        /// Logout the current user
        /// </summary>
        /// <returns>success or failure</returns>
        public async Task<bool> LogoutAsync()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException("Microsoft Graph not initialized.");
            }

            return await _authentication.LogoutAsync(_authenticationModel);
        }

        /// <summary>
        /// Get code associated to the device.
        /// This code is used to authenticate the device from another one.
        /// </summary>
        /// <returns>Code</returns>
        public async Task InitializeForDeviceCodeAsync()
        {
            _authentication = new MicrosoftGraphAuthenticationHelper();
            _deviceCode = await _authentication.GetCode(_appClientId);
        }

        /// <summary>
        /// Prompt the user to enter the device code and credential.
        /// </summary>
        /// <returns>Useless result (always return UserCancel)</returns>
        public Task<WebAuthenticationResult> AuthenticateForDeviceAsync()
        {
            _authentication = new MicrosoftGraphAuthenticationHelper();
            return _authentication.AuthenticateForDeviceAsync();
        }

        /// <summary>
        /// Login the user from Azure AD and Get Microsoft Graph access token.
        /// </summary>
        /// <remarks>Need Sign in and read user profile scopes (User.Read)</remarks>
        /// <returns>Returns success or failure of login attempt.</returns>
        public async Task<bool> LoginAsync()
        {
            _isConnected = false;
            if (!_isInitialized)
            {
                throw new InvalidOperationException("Microsoft Graph not initialized.");
            }

            _authentication = new MicrosoftGraphAuthenticationHelper();
            string accessToken = null;
            if (_deviceCode != null)
            {
                accessToken = await _authentication.GetUserTokenFromDeviceCodeAsync(_appClientId, _deviceCode);
            }
            else if (_authenticationModel == AuthenticationModel.V1)
            {
                accessToken = await _authentication.GetUserTokenAsync(_appClientId);
            }
            else
            {
                accessToken = await _authentication.GetUserTokenV2Async(_appClientId);
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                return _isConnected;
            }

            _isConnected = true;

            _user = new MicrosoftGraphUserService(_graphProvider);

            if ((_servicesToInitialize & ServicesToInitialize.UserProfile) == ServicesToInitialize.UserProfile)
            {
                await GetUserAsyncProfile();
            }

            // if ((_servicesToInitialize & ServicesToInitialize.OneDrive) == ServicesToInitialize.OneDrive)
            // {
            //    _user.InitializeDrive();
            // }
            if ((_servicesToInitialize & ServicesToInitialize.Message) == ServicesToInitialize.Message)
            {
                _user.InitializeMessage();
            }

            if ((_servicesToInitialize & ServicesToInitialize.Event) == ServicesToInitialize.Event)
            {
                _user.InitializeEvent();
            }

            return _isConnected;
        }

        /// <summary>
        /// Create Microsoft Graph client
        /// </summary>
        /// <param name='appClientId'>Azure AD's App client id</param>
        /// <param name="authenticationModel">V1 or V2</param>
        /// <returns>instance of the GraphServiceclient</returns>
        private GraphServiceClient CreateGraphClientProvider(string appClientId, AuthenticationModel authenticationModel)
        {
            return new GraphServiceClient(
                  new DelegateAuthenticationProvider(
                     async (requestMessage) =>
                     {
                         // requestMessage.Headers.Add('outlook.timezone', 'Romance Standard Time');
                         requestMessage.Headers.Authorization =
                                            new AuthenticationHeaderValue(
                                                     "bearer",
                                                     authenticationModel == AuthenticationModel.V1 ?
                                                     await _authentication.GetUserTokenAsync(appClientId).ConfigureAwait(false) :
                                                     await _authentication.GetUserTokenV2Async(appClientId).ConfigureAwait(false));
                         return;
                     }));
        }

        /// <summary>
        /// Initialize a instance of MicrosoftGraphUserService class
        /// </summary>
        /// <returns><see cref="Task"/> representing the asynchronous operation.</returns>
        private async Task GetUserAsyncProfile()
        {
            MicrosoftGraphUserFields[] selectedFields =
            {
                MicrosoftGraphUserFields.Id
            };

            await _user.GetProfileAsync(selectedFields);
        }
    }
}
