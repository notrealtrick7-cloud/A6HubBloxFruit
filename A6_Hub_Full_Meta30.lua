--[[
    A6 Hub · Discord Button
    Nút: A6 Hub Updated
    Click → copy https://discord.gg/ZkGwEUGJv + thông báo
]]

local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local LP = Players.LocalPlayer

local DISCORD = "https://discord.gg/ZkGwEUGJv"

local function notify(text)
    pcall(function()
        local RS = game:GetService("ReplicatedStorage")
        require(RS.Notification).new("<Color=Cyan>" .. text .. "<Color=/>"):Display()
    end)
    pcall(function()
        game:GetService("StarterGui"):SetCore("SendNotification", {
            Title = "A6 Hub",
            Text = text,
            Duration = 3,
        })
    end)
end

local sg = Instance.new("ScreenGui")
sg.Name = "A6DiscordBtn"
sg.ResetOnSpawn = false
sg.Parent = game.CoreGui

local btn = Instance.new("TextButton")
btn.Name = "JoinDiscord"
btn.Parent = sg
btn.Size = UDim2.new(0, 160, 0, 36)
btn.Position = UDim2.new(1, -172, 0, 12)
btn.AnchorPoint = Vector2.new(0, 0)
btn.BackgroundColor3 = Color3.fromRGB(88, 101, 242)
btn.Font = Enum.Font.GothamBold
btn.TextSize = 14
btn.TextColor3 = Color3.fromRGB(255, 255, 255)
btn.Text = "A6 Hub Updated"
btn.AutoButtonColor = true
Instance.new("UICorner", btn).CornerRadius = UDim.new(0, 8)

local stroke = Instance.new("UIStroke", btn)
stroke.Color = Color3.fromRGB(200, 210, 255)
stroke.Thickness = 1.2

btn.MouseButton1Click:Connect(function()
    pcall(setclipboard, DISCORD)
    notify("Copied link discord")
    -- pulse
    TweenService:Create(btn, TweenInfo.new(0.12), {BackgroundColor3 = Color3.fromRGB(60, 200, 120)}):Play()
    task.delay(0.35, function()
        TweenService:Create(btn, TweenInfo.new(0.2), {BackgroundColor3 = Color3.fromRGB(88, 101, 242)}):Play()
    end)
end)

print("[A6] Discord button ready")
