Set olApp = CreateObject("Outlook.Application") 
Set olRules = olApp.Session.DefaultStore.GetRules()

RuleName = "Urgent Alert Notification"

' Check if rule already exists
RuleExists = False
For Each Rule In olRules
    If Rule.Name = RuleName Then
        RuleExists = True
        Exit For
    End If
Next

If Not RuleExists Then
    Set newRule = olRules.Create(RuleName, 0) ' 0 = olRuleReceive
    
    ' Condition: Email from "Bishnu Prasad Panigrahi"
    Set ConditionFrom = newRule.Conditions.SenderName
    ConditionFrom.Enabled = True
    ConditionFrom.Text = Array("Bishnu Prasad Panigrahi")

    ' Condition: Subject contains "Urgent Alert"
    Set ConditionSubject = newRule.Conditions.Subject
    ConditionSubject.Enabled = True
    ConditionSubject.Text = Array("Urgent Alert")

    ' Action: Play Sound
    Set ActionPlaySound = newRule.Actions.PlaySound
    ActionPlaySound.Enabled = True
    ActionPlaySound.FilePath = "C:\Music\IPL-Alert.mp3"

    ' Save rule
    olRules.Save()
End If
