﻿using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;
using JwtAuthenticationDotNet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthenticationDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new();

        private readonly IAuthService _authService;

        public AuthController
        (
            IAuthService authService
        )
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDto request)
        {
            var user = await _authService.RegisterAsyn(request);

            if(user is null) return BadRequest("User already exists");

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserDto request)
        {
            var result = await _authService.LoginAsyn(request);

            if (result is null) return BadRequest("User Not Found");

            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await _authService.RefreshToken(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null) return BadRequest("Invalid Token");

            return Ok(result);
        }

        [HttpGet("auth-user")]
        [Authorize]
        public async Task<IActionResult> AuthenticatedUserEndpoint()
        {
            return Ok("You are Authenticated!!!!");
        }

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminUserEndpoint()
        {
            return Ok("You are an admin");
        }
    }
}
