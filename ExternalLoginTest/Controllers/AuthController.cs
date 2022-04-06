using ExternalLoginTest.Models;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using System.Security.Claims;

namespace ExternalLoginTest.Controllers;
[Route("[controller]/[action]")]
[AllowAnonymous]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthController(SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider)
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Auth");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet]
    public async Task<IActionResult> ExternalLoginCallback()
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            //return RedirectToAction(nameof(Login));
            return BadRequest();
        }
        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: false);
        if (signInResult.Succeeded)
        {
            return RedirectToAction(nameof(Index));
        }

        ViewData["Provider"] = info.LoginProvider;
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        return View("ExternalLogin", new ExternalLoginModel { Email = email });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
            return Content("system has error");

        var user = await _userManager.FindByEmailAsync(model.Email);
        IdentityResult result = new();

        if (user != null)
        {
            var logins = await _userManager.GetLoginsAsync(user);
            if (!logins.Any())
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (!result.Succeeded)
                {
                    ModelState.TryAddModelError(string.Empty, result.Errors.Select(_ => _.Description).FirstOrDefault());
                    return View(nameof(ExternalLogin), model);
                }
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction("Index", "Home");
        }
        else
        {
            model.Principal = info.Principal;

            user = new(model.Email)
            {
                Email = model.Email
            };

            result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    //TODO: Send an email for the email confirmation and add a default role as in the Register action
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
            }
        }

        foreach (var error in result.Errors)
        {
            ModelState.TryAddModelError(error.Code, error.Description);
        }

        return View(nameof(ExternalLogin), model);
    }
}