package com.privacylion.btcdid

import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp
import androidx.compose.material3.Text
import kotlinx.coroutines.delay

/**
 * Splash screen with animated cursive "S" using Dancing Script font.
 */
class SplashActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            SplashScreen(
                onAnimationComplete = {
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                    overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                }
            )
        }
    }
}

@Composable
fun SplashScreen(onAnimationComplete: () -> Unit) {
    // Load Dancing Script font
    val dancingScript = FontFamily(Font(R.font.dancing_script))
    
    // Animation states
    var startAnimation by remember { mutableStateOf(false) }
    
    // Scale animation: 0.5 -> 1.0
    val scale by animateFloatAsState(
        targetValue = if (startAnimation) 1f else 0.5f,
        animationSpec = tween(
            durationMillis = 800,
            easing = FastOutSlowInEasing
        ),
        label = "scale"
    )
    
    // Alpha animation: 0 -> 1
    val alpha by animateFloatAsState(
        targetValue = if (startAnimation) 1f else 0f,
        animationSpec = tween(
            durationMillis = 600,
            easing = FastOutSlowInEasing
        ),
        label = "alpha"
    )
    
    // Start animation after short delay
    LaunchedEffect(Unit) {
        delay(200)
        startAnimation = true
    }
    
    // Navigate after animation completes
    LaunchedEffect(startAnimation) {
        if (startAnimation) {
            delay(1500) // Wait for animation + pause
            onAnimationComplete()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF3B82F6),
                        Color(0xFF8B5CF6)
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY)
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        // Large cursive S using Dancing Script font
        Text(
            text = "S",
            style = TextStyle(
                fontFamily = dancingScript,
                fontSize = 280.sp,  // MUCH LARGER
                color = Color.White
            ),
            modifier = Modifier
                .scale(scale)
                .alpha(alpha)
        )
    }
}
