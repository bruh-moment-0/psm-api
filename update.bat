@echo off
set /p commitmsg=message: 
git add .
git commit -m "%commitmsg%"
git push
echo pushed!
pause