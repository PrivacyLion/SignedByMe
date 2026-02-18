package com.privacylion.btcdid

import android.animation.ValueAnimator
import android.content.Intent
import android.graphics.*
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.activity.ComponentActivity

/**
 * Splash screen with animated cursive "S" handwriting effect.
 * The S draws itself elegantly, then transitions to the main app.
 */
class SplashActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val animatedView = AnimatedSignatureView(this)
        setContentView(animatedView)
        
        animatedView.startAnimation {
            // Animation complete, go to main activity
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            // Fade transition
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
        }
    }
}

/**
 * Custom view that shows animated cursive "S" with fade-in and scale effect.
 * Uses Dancing Script font for authentic cursive look.
 */
class AnimatedSignatureView(context: android.content.Context) : View(context) {
    
    private val gradientColors = intArrayOf(
        Color.parseColor("#3B82F6"),
        Color.parseColor("#8B5CF6")
    )
    
    private var animatedAlpha = 0f
    private var animatedScale = 0.8f
    private var onComplete: (() -> Unit)? = null
    
    private var backgroundGradient: LinearGradient? = null
    private val backgroundPaint = Paint()
    
    // Text paint for the S
    private val textPaint: Paint
    private val glowPaint: Paint
    
    init {
        // Load Dancing Script font for authentic cursive look
        val dancingScript = try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                context.resources.getFont(R.font.dancing_script)
            } else {
                Typeface.create("cursive", Typeface.NORMAL)
            }
        } catch (e: Exception) {
            Typeface.create("cursive", Typeface.NORMAL)
        }
        
        textPaint = Paint().apply {
            color = Color.WHITE
            textSize = 300f
            typeface = dancingScript
            isAntiAlias = true
            textAlign = Paint.Align.CENTER
        }
        
        glowPaint = Paint().apply {
            color = Color.WHITE
            textSize = 300f
            typeface = dancingScript
            isAntiAlias = true
            textAlign = Paint.Align.CENTER
            maskFilter = BlurMaskFilter(30f, BlurMaskFilter.Blur.NORMAL)
            alpha = 80
        }
        
        // Disable hardware acceleration for blur effect
        setLayerType(LAYER_TYPE_SOFTWARE, null)
    }
    
    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        
        // Create background gradient
        backgroundGradient = LinearGradient(
            0f, 0f, w.toFloat(), h.toFloat(),
            gradientColors, null, Shader.TileMode.CLAMP
        )
        backgroundPaint.shader = backgroundGradient
        
        // Scale text size based on screen
        val fontSize = minOf(w, h) * 0.5f
        textPaint.textSize = fontSize
        glowPaint.textSize = fontSize
    }
    
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        
        // Draw gradient background
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundPaint)
        
        val cx = width / 2f
        val cy = height / 2f
        
        // Apply scale transformation
        canvas.save()
        canvas.scale(animatedScale, animatedScale, cx, cy)
        
        // Set alpha
        glowPaint.alpha = (80 * animatedAlpha).toInt()
        textPaint.alpha = (255 * animatedAlpha).toInt()
        
        // Calculate vertical center (text draws from baseline)
        val textBounds = android.graphics.Rect()
        textPaint.getTextBounds("S", 0, 1, textBounds)
        val textY = cy + textBounds.height() / 2f
        
        // Draw glow first
        canvas.drawText("S", cx, textY, glowPaint)
        
        // Draw text
        canvas.drawText("S", cx, textY, textPaint)
        
        canvas.restore()
    }
    
    fun startAnimation(onComplete: () -> Unit) {
        this.onComplete = onComplete
        
        // Wait a moment before starting
        postDelayed({
            // Fade in and scale up animation
            ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 800
                interpolator = AccelerateDecelerateInterpolator()
                addUpdateListener { animator ->
                    val value = animator.animatedValue as Float
                    this@AnimatedSignatureView.animatedAlpha = value
                    this@AnimatedSignatureView.animatedScale = 0.8f + (0.2f * value)
                    this@AnimatedSignatureView.invalidate()
                }
                addListener(object : android.animation.Animator.AnimatorListener {
                    override fun onAnimationStart(animation: android.animation.Animator) {}
                    override fun onAnimationCancel(animation: android.animation.Animator) {}
                    override fun onAnimationRepeat(animation: android.animation.Animator) {}
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        // Brief pause to admire, then continue
                        postDelayed({
                            this@AnimatedSignatureView.onComplete?.invoke()
                        }, 500)
                    }
                })
                start()
            }
        }, 200)
    }
}
