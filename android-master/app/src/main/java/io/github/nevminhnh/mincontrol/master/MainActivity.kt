package io.github.nevminhnh.mincontrol.master

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import io.github.nevminhnh.mincontrol.master.ui.MinControlApp
import io.github.nevminhnh.mincontrol.master.ui.theme.MinControlTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MinControlTheme { MinControlApp() } }
    }
}
