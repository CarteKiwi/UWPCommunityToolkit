// ******************************************************************
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

using System.Numerics;
using Microsoft.Toolkit.Uwp.UI.Extensions;
using Windows.UI.Composition;

namespace Microsoft.Toolkit.Uwp.UI.Animations
{
    /// <summary>
    /// Animation that animates a value of type <see cref="Vector2"/>
    /// </summary>
    public class Vector2Animation : TypedAnimationBase<Vector2KeyFrame, string>
    {
        /// <inheritdoc/>
        protected override KeyFrameAnimation GetTypedAnimationFromCompositor(Compositor compositor)
        {
            return compositor.CreateVector2KeyFrameAnimation();
        }

        /// <inheritdoc/>
        protected override void InsertKeyFrameToTypedAnimation(KeyFrameAnimation animation, Vector2KeyFrame keyFrame)
        {
            (animation as Vector2KeyFrameAnimation).InsertKeyFrame((float)keyFrame.Key, keyFrame.Value.ToVector2());
        }
    }
}
